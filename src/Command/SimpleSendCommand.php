<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:smtp:simple-send',
    description: 'Send an email through SMTP using simple socket connection',
)]
class SimpleSendCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('host', null, InputOption::VALUE_OPTIONAL, 'SMTP host to connect to', 'localhost')
            ->addOption('port', 'p', InputOption::VALUE_OPTIONAL, 'SMTP port to connect to', 587)
            ->addOption('from', 'f', InputOption::VALUE_OPTIONAL, 'From email address', 'sender@example.com')
            ->addOption('to', 't', InputOption::VALUE_OPTIONAL, 'To email address', 'recipient@example.com')
            ->addOption('subject', 's', InputOption::VALUE_OPTIONAL, 'Email subject', 'Test email from MailHarbor')
            ->addOption('body', 'b', InputOption::VALUE_OPTIONAL, 'Email body', 'This is a test email.')
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
        $body = $input->getOption('body');
        $useTls = $input->getOption('tls');
        
        $io->title('Simple SMTP Test');
        $io->text([
            "Host: $host:$port",
            "From: $from",
            "To: $to",
            "Subject: $subject",
            "TLS: " . ($useTls ? 'Yes' : 'No'),
        ]);
        
        try {
            // Ouvrir la connection au serveur SMTP
            $io->text('Connecting to SMTP server...');
            $socket = @fsockopen($host, $port, $errno, $errstr, 30);
            
            if (!$socket) {
                throw new \RuntimeException("Failed to connect to SMTP server: $errstr ($errno)");
            }
            
            // Rendre le socket bloquant pour une communication plus facile
            stream_set_blocking($socket, true);
            
            // Attendre et lire la réponse du serveur
            $response = $this->readResponse($socket, $io);
            
            // Envoyer EHLO
            $io->text('Sending EHLO...');
            $this->sendCommand($socket, "EHLO localhost", $io);
            
            // Si TLS est activé, négocier STARTTLS
            if ($useTls) {
                $io->text('Initiating STARTTLS...');
                $this->sendCommand($socket, "STARTTLS", $io);
                
                $io->text('Starting TLS negotiation...');
                if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new \RuntimeException("Failed to enable TLS encryption");
                }
                
                $io->success('TLS negotiation successful');
                
                // Après STARTTLS, il faut renvoyer EHLO
                $io->text('Sending EHLO after TLS...');
                $this->sendCommand($socket, "EHLO localhost", $io);
            }
            
            // Envoyer MAIL FROM
            $io->text('Sending MAIL FROM...');
            $this->sendCommand($socket, "MAIL FROM:<$from>", $io);
            
            // Envoyer RCPT TO
            $io->text('Sending RCPT TO...');
            $this->sendCommand($socket, "RCPT TO:<$to>", $io);
            
            // Envoyer DATA
            $io->text('Sending DATA command...');
            $response = $this->sendCommand($socket, "DATA", $io);
            
            // Vérifier si nous avons bien reçu le code 354
            if (substr($response, 0, 3) !== '354') {
                throw new \RuntimeException("Server did not accept DATA command: $response");
            }
            
            // Préparer le contenu de l'email
            $emailContent = "From: $from\r\n";
            $emailContent .= "To: $to\r\n";
            $emailContent .= "Subject: $subject\r\n";
            $emailContent .= "Date: " . date('r') . "\r\n";
            $emailContent .= "\r\n"; // Ligne vide entre headers et corps
            $emailContent .= "$body\r\n";
            $emailContent .= ".\r\n"; // Marqueur de fin de DATA
            
            // Envoyer le contenu de l'email
            $io->text('Sending email content...');
            fwrite($socket, $emailContent);
            $response = $this->readResponse($socket, $io);
            
            // Envoyer QUIT
            $io->text('Sending QUIT...');
            $this->sendCommand($socket, "QUIT", $io);
            
            // Fermer la connexion
            fclose($socket);
            
            $io->success('Email sent successfully!');
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error('Error: ' . $e->getMessage());
            
            if (isset($socket) && is_resource($socket)) {
                fclose($socket);
            }
            
            return Command::FAILURE;
        }
    }
    
    /**
     * Envoie une commande SMTP et retourne la réponse
     */
    private function sendCommand($socket, string $command, SymfonyStyle $io): string
    {
        $io->text("C: $command");
        fwrite($socket, "$command\r\n");
        return $this->readResponse($socket, $io);
    }
    
    /**
     * Lit la réponse du serveur SMTP
     */
    private function readResponse($socket, SymfonyStyle $io): string
    {
        $response = '';
        while (($line = fgets($socket, 515)) !== false) {
            $response .= $line;
            $io->text("S: " . trim($line));
            
            // Si le 4ème caractère est un espace, c'est la dernière ligne de la réponse
            if (isset($line[3]) && $line[3] == ' ') {
                break;
            }
        }
        
        if (empty($response)) {
            throw new \RuntimeException("No response received from server");
        }
        
        return trim($response);
    }
}