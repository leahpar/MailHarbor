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
    ];
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
            'data' => ''
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
            $this->disconnectClient($clientId);
            return "221 Goodbye\r\n";
        }
        
        if (strpos($commandUpper, 'HELO') === 0 || strpos($commandUpper, 'EHLO') === 0) {
            $hostname = substr($command, 5);
            if (!empty($hostname)) {
                $this->clientStates[$clientId]['hostname'] = trim($hostname);
            }
            return "250 MailHarbor\r\n";
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
            
            // TODO: Store the email in the file system (this will be implemented in a future task)
            
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
}
