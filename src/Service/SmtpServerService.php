<?php

namespace App\Service;

class SmtpServerService
{
    private bool $isRunning = false;
    private $socket = null;
    private array $clients = [];
    private array $clientBuffers = [];
    private array $clientStates = [];
    private array $config = [
        'port' => 25,
        'host' => '0.0.0.0',
        'maxConnections' => 10,
        'timeout' => 30,
    ];

    public function __construct()
    {
        // Constructor might receive logger and other dependencies later
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
        $this->socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->socket === false) {
            throw new \RuntimeException('Failed to create socket: ' . socket_strerror(socket_last_error()));
        }
        
        // Set socket options
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        
        // Bind the socket to an address/port
        if (!@socket_bind($this->socket, $this->config['host'], $this->config['port'])) {
            throw new \RuntimeException('Failed to bind socket: ' . socket_strerror(socket_last_error($this->socket)));
        }
        
        // Start listening on the socket
        if (!@socket_listen($this->socket, $this->config['maxConnections'])) {
            throw new \RuntimeException('Failed to listen on socket: ' . socket_strerror(socket_last_error($this->socket)));
        }
        
        // Set socket to non-blocking mode for accept operations
        socket_set_nonblock($this->socket);
        
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
                socket_close($client);
            }
        }
        $this->clients = [];
        
        // Close the main server socket
        if ($this->socket !== null) {
            socket_close($this->socket);
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
        $clientSocket = @socket_accept($this->socket);
        
        // If no connection is waiting, socket_accept returns false in non-blocking mode
        if ($clientSocket === false) {
            return;
        }
        
        // Set client socket to non-blocking mode
        socket_set_nonblock($clientSocket);
        
        // Get client IP address
        socket_getpeername($clientSocket, $clientIp);
        
        // Store the client socket and initialize its state
        $clientId = (int) $clientSocket;
        $this->clients[$clientId] = $clientSocket;
        $this->clientBuffers[$clientId] = '';
        $this->clientStates[$clientId] = [
            'connected_at' => time(),
            'last_activity' => time(),
            'state' => 'new',
            'ip' => $clientIp
        ];
        
        // Send greeting to client
        $greeting = "220 MailHarbor SMTP Service Ready\r\n";
        socket_write($clientSocket, $greeting, strlen($greeting));
    }
    
    /**
     * Handle data from existing client connections
     */
    private function handleClientData(): void
    {
        foreach ($this->clients as $clientId => $clientSocket) {
            // Read available data from client (non-blocking)
            $buffer = '';
            $bytes = @socket_recv($clientSocket, $buffer, 1024, 0);
            
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
                        
                        // Process SMTP command (to be implemented)
                        $response = $this->processSmtpCommand($clientId, $command);
                        
                        // Send response to client
                        socket_write($clientSocket, $response, strlen($response));
                    }
                }
            }
        }
    }
    
    /**
     * Process a single SMTP command
     * 
     * @param int $clientId The client ID
     * @param string $command The SMTP command to process
     * @return string The response to send back to the client
     */
    private function processSmtpCommand(int $clientId, string $command): string
    {
        // For now just return a placeholder response based on the command
        // This will be implemented in detail in the next task
        
        // Convert command to uppercase for easier matching
        $commandUpper = strtoupper($command);
        
        // Basic command handling placeholders
        if (strpos($commandUpper, 'QUIT') === 0) {
            $this->disconnectClient($clientId);
            return "221 Goodbye\r\n";
        }
        
        if (strpos($commandUpper, 'HELO') === 0 || strpos($commandUpper, 'EHLO') === 0) {
            return "250 MailHarbor\r\n";
        }
        
        // Default response
        return "500 Command not recognized\r\n";
    }
    
    /**
     * Disconnect a client and clean up its resources
     * 
     * @param int $clientId The client ID to disconnect
     */
    private function disconnectClient(int $clientId): void
    {
        if (isset($this->clients[$clientId])) {
            socket_close($this->clients[$clientId]);
            unset($this->clients[$clientId]);
            unset($this->clientBuffers[$clientId]);
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
            if ($now - $state['last_activity'] > $timeout) {
                // This connection has timed out
                $this->disconnectClient($clientId);
            }
        }
    }
}
