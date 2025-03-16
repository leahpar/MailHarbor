<?php

namespace App\Service;

use Socket;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SmtpServerService
{
    private bool $isRunning = false;
    private mixed $socket;
    private array $clients = [];
    private array $clientBuffers = [];
    private array $clientStates = [];
    private array $config = [
        'port' => 25,
        'host' => '0.0.0.0',
        'maxConnections' => 10,
        'timeout' => 30,
        'debug' => 0, // 0 = minimal, 1 = normal, 2 = verbose, 3 = debug
        'tls_enabled' => true,
        'tls_cert_file' => __DIR__ . '/../../var/certs/cert.pem',
        'tls_key_file' => __DIR__ . '/../../var/certs/privkey.pem',
        'tls_passphrase' => null,
    ];
    private $sslContext = null;
    private ?LoggerInterface $logger = null;
    private ?OutputInterface $output = null;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }
    
    /**
     * Set console output for real-time logging
     */
    public function setOutput(OutputInterface $output): void
    {
        $this->output = $output;
    }
    
    /**
     * Start the SMTP server
     *
     * @param array $config Optional configuration overrides
     * @return bool True if server started successfully
     */
    public function start(array $config = []): bool
    {
        if ($this->isRunning) {
            return true;
        }
        
        // Merge provided config with defaults
        $this->config = array_merge($this->config, $config);
        
        // Create a socket
        $this->log('Creating socket...', 1);
        $this->socket = @\socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->socket === false) {
            $error = 'Failed to create socket: ' . \socket_strerror(\socket_last_error());
            $this->log($error, 0, 'error');
            throw new \RuntimeException($error);
        }
        
        // Set socket options
        $this->log('Setting socket options...', 2);
        \socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        
        // Bind the socket to an address/port
        $this->log("Binding to {$this->config['host']}:{$this->config['port']}...", 1);
        if (!@\socket_bind($this->socket, $this->config['host'], $this->config['port'])) {
            $error = 'Failed to bind socket: ' . \socket_strerror(\socket_last_error($this->socket));
            $this->log($error, 0, 'error');
            throw new \RuntimeException($error);
        }
        
        // Start listening on the socket
        $this->log("Listening with max connections: {$this->config['maxConnections']}...", 1);
        if (!@\socket_listen($this->socket, $this->config['maxConnections'])) {
            $error = 'Failed to listen on socket: ' . \socket_strerror(\socket_last_error($this->socket));
            $this->log($error, 0, 'error');
            throw new \RuntimeException($error);
        }
        
        // Set socket to non-blocking mode for accept operations
        $this->log('Setting socket to non-blocking mode...', 2);
        \socket_set_nonblock($this->socket);
        
        // Set up SSL context for TLS if enabled
        if ($this->config['tls_enabled']) {
            $this->setUpSslContext();
        }
        
        $this->isRunning = true;
        return true;
    }
    
    /**
     * Stop the SMTP server
     */
    public function stop(): bool
    {
        if (!$this->isRunning) {
            return true;
        }
        
        // Close all client connections
        foreach ($this->clients as $client) {
            if (is_resource($client)) {
                \socket_close($client);
            }
        }
        $this->clients = [];
        
        // Close the main server socket
        if ($this->socket !== null) {
            \socket_close($this->socket);
            $this->socket = null;
        }
        
        $this->isRunning = false;
        return true;
    }
    
    /**
     * Check if the server is currently running
     */
    public function isRunning(): bool
    {
        return $this->isRunning;
    }
    
    /**
     * Get current server configuration
     */
    public function getConfig(): array
    {
        return $this->config;
    }
    
    /**
     * Process incoming connections and handle client data
     * This method should be called in a loop by the command
     */
    public function processConnections(): void
    {
        if (!$this->isRunning) {
            return;
        }
        
        // Check for new connections
        $this->acceptNewConnections();
        
        // Process data from existing connections
        $this->handleClientData();
        
        // Clean up timed out connections
        $this->cleanupTimedOutConnections();
    }
    
    /**
     * Accept new client connections
     */
    private function acceptNewConnections(): void
    {
        // Only accept new connections if we haven't reached max connections
        if (count($this->clients) >= $this->config['maxConnections']) {
            return;
        }
        
        // Try to accept a new connection
        $clientSocket = @\socket_accept($this->socket);
        
        // If no connection is waiting, socket_accept returns false in non-blocking mode
        if ($clientSocket === false) {
            return;
        }
        
        // Set client socket to non-blocking mode
        \socket_set_nonblock($clientSocket);
        
        // Get client IP address
        \socket_getpeername($clientSocket, $clientIp);
        
        // Store the client socket and initialize its state
        $clientId = uniqid('client_', true);
        $this->clients[$clientId] = $clientSocket;
        $this->clientBuffers[$clientId] = '';
        $this->clientStates[$clientId] = [
            'connected_at' => time(),
            'last_activity' => time(),
            'state' => 'command', // 'command' or 'data'
            'ip' => $clientIp,
            'hostname' => '',
            'mail_from' => '',
            'rcpt_to' => [],
            'data' => '',
            'disconnect_after_response' => false,
            'tls' => false,
            'upgrade_to_tls' => false
        ];
        
        $this->log("New client connected from $clientIp (ID: $clientId)", 1);
        
        // Send greeting to client
        $greeting = "220 MailHarbor SMTP Service Ready\r\n";
        \socket_write($clientSocket, $greeting, strlen($greeting));
        $this->log("Sent to client $clientId: $greeting", 2);
    }
    
    /**
     * Handle data from existing client connections
     */
    private function handleClientData(): void
    {
        foreach ($this->clients as $clientId => $clientSocket) {
            // Read available data from client (non-blocking)
            $buffer = '';
            $bytes = @\socket_recv($clientSocket, $buffer, 1024, 0);
            
            // Check if connection was closed or error occurred
            if ($bytes === 0 || $bytes === false) {
                // Connection closed or error
                $this->disconnectClient($clientId);
                continue;
            }
            
            // If we received data, process it
            if ($bytes > 0) {
                $this->clientBuffers[$clientId] .= $buffer;
                $this->clientStates[$clientId]['last_activity'] = time();
                
                // Check if we have a complete command (ending with CR+LF)
                if (strpos($this->clientBuffers[$clientId], "\r\n") !== false) {
                    // Extract complete commands and process them
                    $commands = explode("\r\n", $this->clientBuffers[$clientId]);
                    $this->clientBuffers[$clientId] = array_pop($commands); // Keep incomplete command in buffer
                    
                    foreach ($commands as $command) {
                        if (empty($command)) {
                            continue;
                        }
                        
                        // Check if we're in DATA mode and this is not the end marker
                        if ($this->clientStates[$clientId]['state'] === 'data' && $command !== '.') {
                            // In DATA mode, just accumulate the data
                            $this->clientStates[$clientId]['data'] .= $command . "\r\n";
                            continue;
                        }
                        
                        // Process SMTP command
                        $this->log("Received from client $clientId: $command", 2);
                        $response = $this->processSmtpCommand($clientId, $command);
                        
                        // Send response to client
                        \socket_write($clientSocket, $response, strlen($response));
                        $this->log("Sent to client $clientId: $response", 2);
                        
                        // Check if we need to handle TLS upgrade
                        if (isset($this->clientStates[$clientId]['upgrade_to_tls']) && 
                            $this->clientStates[$clientId]['upgrade_to_tls'] === true) {
                            $this->upgradeToTls($clientId);
                        }
                        
                        // Check if client should be disconnected after this response
                        if (isset($this->clientStates[$clientId]['disconnect_after_response']) && 
                            $this->clientStates[$clientId]['disconnect_after_response'] === true) {
                            $this->disconnectClient($clientId);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Process a single SMTP command
     * 
     * @param string $clientId The client ID
     * @param string $command The SMTP command to process
     * @return string The response to send back to the client
     */
    private function processSmtpCommand(string $clientId, string $command): string
    {
        // Convert command to uppercase for easier matching
        $commandUpper = strtoupper($command);
        
        // Basic command handling
        if (strpos($commandUpper, 'QUIT') === 0) {
            // We need to return the response first, then disconnect the client
            // The disconnect will happen after the response is sent
            $this->clientStates[$clientId]['disconnect_after_response'] = true;
            return "221 Goodbye\r\n";
        }
        
        if (strpos($commandUpper, 'EHLO') === 0) {
            $hostname = substr($command, 5);
            if (!empty($hostname)) {
                $this->clientStates[$clientId]['hostname'] = trim($hostname);
            }
            
            // Respond with capabilities, including STARTTLS if enabled
            $response = "250-MailHarbor\r\n";
            $response .= "250-SIZE 10240000\r\n"; // 10MB max message size
            $response .= "250-8BITMIME\r\n";
            
            // Only advertise STARTTLS if TLS is enabled and we're not already in TLS mode
            if ($this->config['tls_enabled'] && !$this->clientStates[$clientId]['tls']) {
                $response .= "250-STARTTLS\r\n";
            }
            
            $response .= "250 HELP\r\n";
            return $response;
        }
        
        if (strpos($commandUpper, 'HELO') === 0) {
            $hostname = substr($command, 5);
            if (!empty($hostname)) {
                $this->clientStates[$clientId]['hostname'] = trim($hostname);
            }
            return "250 MailHarbor\r\n";
        }
        
        // Handle STARTTLS command
        if ($commandUpper === 'STARTTLS' && $this->config['tls_enabled'] && !$this->clientStates[$clientId]['tls']) {
            // Mark this connection for TLS upgrade
            $this->clientStates[$clientId]['upgrade_to_tls'] = true;
            return "220 Ready to start TLS\r\n";
        }
        
        if (strpos($commandUpper, 'MAIL FROM:') === 0) {
            $sender = $this->extractEmail($command, 'MAIL FROM:');
            $this->clientStates[$clientId]['mail_from'] = $sender;
            return "250 OK\r\n";
        }
        
        if (strpos($commandUpper, 'RCPT TO:') === 0) {
            $recipient = $this->extractEmail($command, 'RCPT TO:');
            if (!isset($this->clientStates[$clientId]['rcpt_to'])) {
                $this->clientStates[$clientId]['rcpt_to'] = [];
            }
            $this->clientStates[$clientId]['rcpt_to'][] = $recipient;
            return "250 OK\r\n";
        }
        
        if (strpos($commandUpper, 'DATA') === 0) {
            $this->clientStates[$clientId]['state'] = 'data';
            return "354 Start mail input; end with <CRLF>.<CRLF>\r\n";
        }
        
        // Handle DATA state separately
        if ($this->clientStates[$clientId]['state'] === 'data' && $command === '.') {
            $this->clientStates[$clientId]['state'] = 'command';
            
            // Extract information about the email
            $from = $this->clientStates[$clientId]['mail_from'];
            $to = implode(', ', $this->clientStates[$clientId]['rcpt_to']);
            $dataSize = strlen($this->clientStates[$clientId]['data']);
            
            $this->log("Email received from client $clientId - From: $from, To: $to, Size: $dataSize bytes", 1);
            
            // Store the email in the file system
            $result = $this->storeEmail(
                $from,
                $this->clientStates[$clientId]['rcpt_to'],
                $this->clientStates[$clientId]['data']
            );
            
            if (!$result) {
                $this->log("Error storing email from $from to $to", 0, 'error');
                return "451 Requested action aborted: local error in processing\r\n";
            }
            
            // Clear the email data after processing
            $this->clientStates[$clientId]['data'] = '';
            
            return "250 OK: message queued\r\n";
        }
        
        // Default response
        return "500 Command not recognized\r\n";
    }
    
    /**
     * Extract email address from SMTP command
     */
    private function extractEmail(string $command, string $prefix): string
    {
        $email = substr($command, strlen($prefix));
        // Strip < and > if present
        $email = trim(str_replace(['<', '>'], '', $email));
        return $email;
    }
    
    /**
     * Disconnect a client and clean up its resources
     * 
     * @param string $clientId The client ID to disconnect
     */
    private function disconnectClient(string $clientId): void
    {
        if (isset($this->clients[$clientId])) {
            \socket_close($this->clients[$clientId]);
            unset($this->clients[$clientId]);
            unset($this->clientBuffers[$clientId]);
            
            $ip = $this->clientStates[$clientId]['ip'] ?? 'unknown';
            $this->log("Client disconnected: $ip (ID: $clientId)", 1);
            
            unset($this->clientStates[$clientId]);
        }
    }
    
    /**
     * Clean up connections that have timed out
     */
    private function cleanupTimedOutConnections(): void
    {
        $now = time();
        $timeout = $this->config['timeout'];
        
        foreach ($this->clientStates as $clientId => $state) {
            $inactiveTime = $now - $state['last_activity'];
            if ($inactiveTime > $timeout) {
                // This connection has timed out
                $this->log("Client timeout after {$inactiveTime}s of inactivity: {$state['ip']} (ID: $clientId)", 1);
                $this->disconnectClient($clientId);
            }
        }
    }
    
    /**
     * Log a message to the logger and/or console output
     *
     * @param string $message The message to log
     * @param int $level The debug level (0-3)
     * @param string $type The type of message (info, error, etc.)
     */
    private function log(string $message, int $level = 0, string $type = 'info'): void
    {
        // Only log if debug level is high enough
        if ($level > $this->config['debug']) {
            return;
        }
        
        // Add timestamp to message
        $timestamp = date('Y-m-d H:i:s');
        $formattedMessage = "[$timestamp] $message";
        
        // Log to logger if available
        if ($this->logger !== null) {
            switch ($type) {
                case 'error':
                    $this->logger->error($formattedMessage);
                    break;
                case 'warning':
                    $this->logger->warning($formattedMessage);
                    break;
                case 'debug':
                    $this->logger->debug($formattedMessage);
                    break;
                case 'info':
                default:
                    $this->logger->info($formattedMessage);
                    break;
            }
        }
        
        // Output to console if available
        if ($this->output !== null) {
            $coloredMessage = $formattedMessage;
            
            // Add color based on type
            switch ($type) {
                case 'error':
                    $coloredMessage = "<error>$formattedMessage</error>";
                    break;
                case 'warning':
                    $coloredMessage = "<comment>$formattedMessage</comment>";
                    break;
                case 'debug':
                    $coloredMessage = "<fg=cyan>$formattedMessage</fg=cyan>";
                    break;
                case 'info':
                default:
                    if ($level === 0) {
                        $coloredMessage = "<info>$formattedMessage</info>";
                    }
                    break;
            }
            
            $this->output->writeln($coloredMessage);
        }
    }
    
    /**
     * Store email data in the file system
     *
     * @param string $from Sender email address
     * @param array $recipients Array of recipient email addresses
     * @param string $data Email content
     * @return bool True if the email was stored successfully
     */
    private function storeEmail(string $from, array $recipients, string $data): bool
    {
        try {
            // Create base directory
            $baseDir = __DIR__ . '/../../var/emails';
            if (!is_dir($baseDir)) {
                mkdir($baseDir, 0777, true);
            }
            
            // Build email content
            $emailContent = "";
            
            // Get timestamp for email
            $timestamp = time();
            $dateTime = date('Y-m-d_H-i-s', $timestamp);
            
            // Add metadata as headers
            $emailContent .= "From: $from\r\n";
            $emailContent .= "To: " . implode(', ', $recipients) . "\r\n";
            $emailContent .= "Date: " . date('r', $timestamp) . "\r\n";
            $emailContent .= "X-MailHarbor-Received: " . date('r', $timestamp) . "\r\n";
            $emailContent .= "X-MailHarbor-From: $from\r\n";
            
            foreach ($recipients as $index => $recipient) {
                $emailContent .= "X-MailHarbor-Recipient-" . ($index + 1) . ": $recipient\r\n";
            }
            
            $emailContent .= "\r\n";
            
            // Add email content
            $emailContent .= $data;
            
            // Store for each recipient
            $stored = false;
            
            foreach ($recipients as $recipient) {
                // Create a sanitized directory name for the recipient
                $recipientDir = $baseDir . '/' . $this->sanitizeEmailForFilename($recipient);
                
                if (!is_dir($recipientDir)) {
                    mkdir($recipientDir, 0777, true);
                }
                
                // Create unique filename for this recipient
                $uniqueId = substr(md5($from . $recipient . $timestamp), 0, 8);
                $filename = $dateTime . '_' . $uniqueId . '.eml';
                $filepath = $recipientDir . '/' . $filename;
                
                // Write to file
                $bytes = file_put_contents($filepath, $emailContent);
                
                if ($bytes === false) {
                    $this->log("Failed to write email to file: $filepath", 0, 'error');
                } else {
                    $this->log("Email for recipient $recipient stored in $filepath ($bytes bytes)", 2);
                    $stored = true;
                }
            }
            
            if ($stored) {
                $this->log("Email from $from to " . count($recipients) . " recipient(s) stored successfully", 1);
                return true;
            } else {
                $this->log("Failed to store email to any recipient", 0, 'error');
                return false;
            }
        } catch (\Exception $e) {
            $this->log("Exception storing email: " . $e->getMessage(), 0, 'error');
            return false;
        }
    }
    
    /**
     * Set up SSL context for TLS encryption
     */
    private function setUpSslContext(): void
    {
        if (!extension_loaded('openssl')) {
            $this->log('OpenSSL extension is not loaded. TLS will not be available.', 0, 'warning');
            $this->config['tls_enabled'] = false;
            return;
        }
        
        // Check if certificate and key files are provided
        if (empty($this->config['tls_cert_file']) || empty($this->config['tls_key_file'])) {
            $this->log('SSL certificate or key file not provided. TLS will not be available.', 0, 'warning');
            $this->config['tls_enabled'] = false;
            return;
        }
        
        // Check if certificate and key files exist
        if (!file_exists($this->config['tls_cert_file']) || !file_exists($this->config['tls_key_file'])) {
            $this->log('SSL certificate or key file not found at: ' . $this->config['tls_cert_file'] . ' or ' . $this->config['tls_key_file'], 0, 'warning');
            $this->log('Creating empty certificate files as placeholders. Replace with real certificates for TLS to work.', 0, 'warning');
            
            // Create directories if they don't exist
            $certDir = dirname($this->config['tls_cert_file']);
            if (!is_dir($certDir)) {
                mkdir($certDir, 0755, true);
            }
            
            // Create empty files as placeholders
            if (!file_exists($this->config['tls_cert_file'])) {
                file_put_contents($this->config['tls_cert_file'], '');
            }
            if (!file_exists($this->config['tls_key_file'])) {
                file_put_contents($this->config['tls_key_file'], '');
            }
            
            $this->log('TLS will be advertised but will not work until proper certificates are provided.', 0, 'warning');
            // We don't disable TLS here, it will just fail when clients try to use it
        }
        
        // Create SSL context
        $this->log('Setting up SSL context...', 1);
        
        // Log the actual cert paths being used
        $certFile = realpath($this->config['tls_cert_file']);
        $keyFile = realpath($this->config['tls_key_file']);
        
        $this->log('Certificate file path: ' . $this->config['tls_cert_file'], 2);
        $this->log('Certificate file exists: ' . (file_exists($this->config['tls_cert_file']) ? 'Yes' : 'No'), 2);
        $this->log('Certificate resolved path: ' . ($certFile ?: 'Not found'), 2);
        $this->log('Certificate file size: ' . (file_exists($this->config['tls_cert_file']) ? filesize($this->config['tls_cert_file']) . ' bytes' : 'N/A'), 2);
        
        $this->log('Key file path: ' . $this->config['tls_key_file'], 2);
        $this->log('Key file exists: ' . (file_exists($this->config['tls_key_file']) ? 'Yes' : 'No'), 2);
        $this->log('Key resolved path: ' . ($keyFile ?: 'Not found'), 2);
        $this->log('Key file size: ' . (file_exists($this->config['tls_key_file']) ? filesize($this->config['tls_key_file']) . ' bytes' : 'N/A'), 2);
        
        // Use the correct paths in the SSL context
        $contextOptions = [
            'ssl' => [
                'local_cert' => $this->config['tls_cert_file'],
                'local_pk' => $this->config['tls_key_file'],
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'disable_compression' => true,
                'SNI_enabled' => true,
                'ciphers' => 'HIGH:!SSLv2:!SSLv3:!TLSv1.0',
            ]
        ];
        
        // Add passphrase if provided
        if (!empty($this->config['tls_passphrase'])) {
            $contextOptions['ssl']['passphrase'] = $this->config['tls_passphrase'];
        }
        
        $this->sslContext = stream_context_create($contextOptions);
        
        $this->log('SSL context created successfully', 1);
        $this->log('Using certificate file: ' . $this->config['tls_cert_file'], 1);
        $this->log('Using key file: ' . $this->config['tls_key_file'], 1);
    }
    
    /**
     * Upgrade a client connection to TLS
     */
    private function upgradeToTls(string $clientId): void
    {
        if (!$this->config['tls_enabled'] || $this->sslContext === null) {
            $this->log("TLS upgrade requested but TLS is not available", 0, 'warning');
            return;
        }
        
        $this->log("Upgrading client $clientId to TLS...", 1);
        
        try {
            // Get the client socket
            $clientSocket = $this->clients[$clientId];
            
            // Convert the socket resource to a stream
            // socket_export_stream() function requires PHP 8.1+
            if (function_exists('socket_export_stream')) {
                $stream = socket_export_stream($clientSocket);
                if (!$stream) {
                    throw new \RuntimeException("Failed to export socket to stream");
                }
            } else {
                // For older PHP versions
                $this->log("socket_export_stream function not available, TLS upgrade may not work correctly", 0, 'warning');
                throw new \RuntimeException("TLS upgrade not supported on this PHP version");
            }
            
            // Enable crypto on the stream
            // We already have the context options applied when creating $this->sslContext
            // No need to set options again, just use the existing stream
            
            // Support multiple TLS protocol versions for better compatibility
            $cryptoMethod = STREAM_CRYPTO_METHOD_TLS_SERVER;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')) {
                $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
            }
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_1_SERVER')) {
                $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_1_SERVER;
            }
            
            $this->log("Attempting TLS handshake with client $clientId", 2);
            if (!stream_socket_enable_crypto($stream, true, $cryptoMethod)) {
                $errorMessage = error_get_last()['message'] ?? 'Unknown error';
                $this->log("TLS error: $errorMessage", 0, 'error');
                throw new \RuntimeException("Failed to enable TLS encryption: $errorMessage");
            }
            
            // Check if stream is still valid
            $streamInfo = stream_get_meta_data($stream);
            $this->log("Stream info after TLS handshake: " . json_encode($streamInfo), 2);
            
            if ($streamInfo['timed_out'] || $streamInfo['eof']) {
                $this->log("Stream error after TLS handshake: timed_out={$streamInfo['timed_out']}, eof={$streamInfo['eof']}", 0, 'error');
                throw new \RuntimeException("Stream error after TLS handshake");
            }
            
            // Mark the client as using TLS
            $this->clientStates[$clientId]['tls'] = true;
            $this->clientStates[$clientId]['upgrade_to_tls'] = false;
            
            // Reset the client state - need to start with a new EHLO after STARTTLS
            $this->clientBuffers[$clientId] = '';
            $this->clientStates[$clientId]['mail_from'] = '';
            $this->clientStates[$clientId]['rcpt_to'] = [];
            $this->clientStates[$clientId]['data'] = '';
            
            $this->log("Successfully upgraded client $clientId to TLS", 1);
            
        } catch (\Exception $e) {
            $this->log("Error upgrading to TLS: " . $e->getMessage(), 0, 'error');
            $this->disconnectClient($clientId);
        }
    }
    
    /**
     * Sanitize an email address to use as a directory name
     *
     * @param string $email Email address
     * @return string Sanitized name
     */
    private function sanitizeEmailForFilename(string $email): string
    {
        // Replace @ with _ and remove any characters not allowed in directory names
        $sanitized = str_replace(['@', '.', '+'], ['_at_', '_dot_', '_plus_'], $email);
        return preg_replace('/[^a-zA-Z0-9_-]/', '', $sanitized);
    }
}
