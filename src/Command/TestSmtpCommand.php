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
            ->addOption('message', 'm', InputOption::VALUE_OPTIONAL, 'Email message', 'This is a test email sent from MailHarbor SMTP test command.');
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
            
            // Read the greeting
            $greeting = $this->readResponse($socket);
            $io->text("Server greeting: $greeting");
            
            // Send HELO command
            $io->text('Sending HELO command...');
            fwrite($socket, "HELO mailharbor-test\r\n");
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
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
            
            fwrite($socket, $email);
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
            // Send QUIT command
            $io->text('Sending QUIT command...');
            fwrite($socket, "QUIT\r\n");
            $response = $this->readResponse($socket);
            $io->text("Response: $response");
            
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
     */
    private function readResponse($socket): string
    {
        $response = '';
        $line = '';
        
        while (($line = fgets($socket, 515)) !== false) {
            $response .= $line;
            
            // SMTP response ends with <CR><LF> and the 4th character
            // is a space if this is the last line of the response
            if (isset($line[3]) && $line[3] == ' ') {
                break;
            }
        }
        
        return trim($response);
    }
}