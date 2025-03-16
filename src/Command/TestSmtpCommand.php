<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:smtp:test',
    description: 'Test the SMTP server by sending an email',
)]
class TestSmtpCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('host', null, InputOption::VALUE_OPTIONAL, 'SMTP host to connect to', 'localhost')
            ->addOption('port', 'p', InputOption::VALUE_OPTIONAL, 'SMTP port to connect to', 25)
            ->addOption('from', 'f', InputOption::VALUE_OPTIONAL, 'From email address', 'test@example.com')
            ->addOption('to', 't', InputOption::VALUE_OPTIONAL, 'To email address', 'recipient@example.com')
            ->addOption('subject', 's', InputOption::VALUE_OPTIONAL, 'Email subject', 'Test email from MailHarbor')
            ->addOption('message', 'm', InputOption::VALUE_OPTIONAL, 'Email message', 'This is a test email sent from MailHarbor SMTP test command.')
            ->addOption('tls', null, InputOption::VALUE_NONE, 'Use STARTTLS to secure the connection');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $host = $input->getOption('host');
        $port = (int) $input->getOption('port');
        $from = $input->getOption('from');
        $to = $input->getOption('to');
        $subject = $input->getOption('subject');
        $message = $input->getOption('message');
        
        $io->title('SMTP Test');
        $io->text([
            'Sending test email with following parameters:',
            "Host: $host:$port",
            "From: $from",
            "To: $to",
            "Subject: $subject",
        ]);
        
        try {
            // Connect to the SMTP server
            $io->text('Connecting to SMTP server...');
            $socket = @fsockopen($host, $port, $errno, $errstr, 30);
            
            if (!$socket) {
                throw new \RuntimeException("Failed to connect to SMTP server: $errstr ($errno)");
            }
            
            $io->text('Connected successfully');
            
            // Set up stream options for debugging
            stream_set_blocking($socket, true);
            
            // Read the greeting
            $greeting = $this->readResponse($socket);
            $io->text("Server greeting: $greeting");
            
            // Send EHLO command instead of HELO to check for STARTTLS support
            $io->text('Sending EHLO command...');
            fwrite($socket, "EHLO mailharbor-test\r\n");
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
            // Check if we need to use TLS
            $useTls = $input->getOption('tls');
            $supportsTls = (strpos($response, "STARTTLS") !== false);
            
            if ($useTls) {
                if (!$supportsTls) {
                    $io->warning('STARTTLS requested but not supported by the server. Continuing without TLS.');
                } else {
                    $io->text('Server supports STARTTLS, initiating TLS handshake...');
                    fwrite($socket, "STARTTLS\r\n");
                    $response = $this->readResponse($socket);
                    $io->text("Response: $response");
                    
                    // Check if the response is positive
                    if (substr($response, 0, 3) === '220') {
                        // Enable TLS on the connection with better compatibility
                        $cryptoMethod = STREAM_CRYPTO_METHOD_TLS_CLIENT;
                        
                        // Add support for different TLS versions
                        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
                            $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
                        }
                        if (defined('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT')) {
                            $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
                        }
                        
                        $io->text('Starting TLS handshake with crypto method: ' . $cryptoMethod);
                        
                        // Remove @ to actually see errors
                        stream_set_blocking($socket, true);
                        stream_set_timeout($socket, 30); // Increase timeout for TLS handshake
                        
                        // Debug information before handshake
                        $io->text('Debug: Stream state before TLS - ' . json_encode(stream_get_meta_data($socket)));
                        
                        // Try TLS handshake with more debug info
                        // Set verbose debug mode
                        $GLOBALS['debug_tls'] = true;
                        
                        // Try TLS handshake
                        $tlsResult = stream_socket_enable_crypto($socket, true, $cryptoMethod);
                        
                        // Reset debug mode
                        $GLOBALS['debug_tls'] = false;
                        
                        if (!$tlsResult) {
                            $error = error_get_last();
                            $errorMsg = $error ? $error['message'] : 'Unknown error';
                            $io->error("TLS handshake failed: $errorMsg");
                            
                            // Show more debug info
                            $io->text('Debug: Stream state after failed TLS - ' . json_encode(stream_get_meta_data($socket)));
                            
                            // Try to read any error response from server
                            $errorResponse = @fgets($socket, 1024);
                            if ($errorResponse) {
                                $io->text("Server response after TLS failure: $errorResponse");
                            }
                            
                            throw new \RuntimeException("Failed to enable TLS: $errorMsg");
                        }
                        
                        $io->success('TLS encryption established');
                        
                        // We need to send EHLO again after STARTTLS
                        $io->text('Sending EHLO command again after TLS...');
                        fwrite($socket, "EHLO mailharbor-test\r\n");
                        $response = $this->readResponse($socket);
                        $io->text("Response: $response");
                    } else {
                        $io->warning('STARTTLS failed, continuing without TLS.');
                    }
                }
            }
            
            // Send MAIL FROM command
            $io->text('Sending MAIL FROM command...');
            fwrite($socket, "MAIL FROM:<$from>\r\n");
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
            // Send RCPT TO command
            $io->text('Sending RCPT TO command...');
            fwrite($socket, "RCPT TO:<$to>\r\n");
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
            // Send DATA command
            $io->text('Sending DATA command...');
            fwrite($socket, "DATA\r\n");
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
            // Send email content
            $io->text('Sending email content...');
            $email = "From: $from\r\n";
            $email .= "To: $to\r\n";
            $email .= "Subject: $subject\r\n";
            $email .= "Date: " . date('r') . "\r\n";
            $email .= "Message-ID: <" . time() . rand(1000, 9999) . "@mailharbor.test>\r\n";
            $email .= "\r\n";
            $email .= "$message\r\n";
            $email .= ".\r\n"; // End of data marker
            
            $result = @fwrite($socket, $email);
            if ($result === false) {
                throw new \RuntimeException("Failed to send email data to server: " . error_get_last()['message'] ?? 'Unknown error');
            }
            
            // Use a longer timeout for DATA response, which may take longer
            $response = $this->readResponse($socket, 10);
            $io->text("Response: $response");
            
            // Send QUIT command
            $io->text('Sending QUIT command...');
            $result = @fwrite($socket, "QUIT\r\n");
            if ($result === false) {
                $io->warning('Failed to send QUIT command, connection may already be closed');
            } else {
                $response = $this->readResponse($socket);
                $io->text("Response: $response");
            }
            
            // Close the connection
            fclose($socket);
            
            $io->success('Email sent successfully');
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error('Error sending email: ' . $e->getMessage());
            
            if (isset($socket) && is_resource($socket)) {
                fclose($socket);
            }
            
            return Command::FAILURE;
        }
    }
    
    /**
     * Read response from SMTP server
     * 
     * @param resource $socket The socket to read from
     * @param int $timeout Optional timeout in seconds
     * @return string The response
     */
    private function readResponse($socket, int $timeout = 5): string
    {
        // Set socket timeout if provided
        if ($timeout > 0) {
            stream_set_timeout($socket, $timeout);
        }
        
        $response = '';
        $line = '';
        
        // Check if socket is still valid
        if (!is_resource($socket) || feof($socket)) {
            return "(Socket closed or not available)";
        }
        
        // More debugging
        $metaBeforeRead = stream_get_meta_data($socket);
        
        while (($line = fgets($socket, 515)) !== false) {
            $response .= $line;
            
            // SMTP response ends with <CR><LF> and the 4th character
            // is a space if this is the last line of the response
            if (isset($line[3]) && $line[3] == ' ') {
                break;
            }
            
            // Check if we timed out
            $info = stream_get_meta_data($socket);
            if ($info['timed_out']) {
                $response .= "(Read timeout occurred)";
                break;
            }
        }
        
        // Get socket status after read
        $metaAfterRead = stream_get_meta_data($socket);
        
        if (empty($response)) {
            // More detailed error information when no response
            $errorInfo = "Stream state before: " . json_encode($metaBeforeRead) . 
                         ", after: " . json_encode($metaAfterRead);
            return "(No response from server or connection closed. $errorInfo)";
        }
        
        return trim($response);
    }
}