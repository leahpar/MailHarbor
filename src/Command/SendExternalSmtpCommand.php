<?php

namespace App\Command;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:smtp:send-external',
    description: 'Send an email through an external SMTP server using PHPMailer',
)]
class SendExternalSmtpCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('host', null, InputOption::VALUE_REQUIRED, 'SMTP host to connect to')
            ->addOption('port', 'p', InputOption::VALUE_OPTIONAL, 'SMTP port to connect to', 587)
            ->addOption('username', 'u', InputOption::VALUE_OPTIONAL, 'SMTP username')
            ->addOption('password', 'w', InputOption::VALUE_OPTIONAL, 'SMTP password')
            ->addOption('from', 'f', InputOption::VALUE_REQUIRED, 'From email address')
            ->addOption('from-name', null, InputOption::VALUE_OPTIONAL, 'From name', 'MailHarbor Test')
            ->addOption('to', 't', InputOption::VALUE_REQUIRED, 'To email address')
            ->addOption('to-name', null, InputOption::VALUE_OPTIONAL, 'To name', '')
            ->addOption('subject', 's', InputOption::VALUE_OPTIONAL, 'Email subject', 'Test email from MailHarbor')
            ->addOption('body', 'b', InputOption::VALUE_OPTIONAL, 'Email body (HTML)', '<h1>Test Email</h1><p>This is a test email sent from MailHarbor using PHPMailer.</p>')
            ->addOption('debug', 'd', InputOption::VALUE_OPTIONAL, 'Debug level (0-4)', 2)
            ->addOption('no-verify-ssl', null, InputOption::VALUE_NONE, 'Disable SSL certificate verification')
            ->addOption('tls', null, InputOption::VALUE_NONE, 'Use STARTTLS to secure the connection')
            ->addOption('ssl', null, InputOption::VALUE_NONE, 'Use SSL/TLS connection (typically port 465)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        // Get options
        $host = $input->getOption('host');
        $port = (int) $input->getOption('port');
        $username = $input->getOption('username');
        $password = $input->getOption('password');
        $from = $input->getOption('from');
        $fromName = $input->getOption('from-name');
        $to = $input->getOption('to');
        $toName = $input->getOption('to-name');
        $subject = $input->getOption('subject');
        $body = $input->getOption('body');
        $debugLevel = (int) $input->getOption('debug');
        $noVerifySsl = $input->getOption('no-verify-ssl');
        $useTls = $input->getOption('tls');
        $useSsl = $input->getOption('ssl');
        
        // Validate required options
        if (!$host) {
            $io->error('The --host option is required');
            return Command::FAILURE;
        }
        
        if (!$from) {
            $io->error('The --from option is required');
            return Command::FAILURE;
        }
        
        if (!$to) {
            $io->error('The --to option is required');
            return Command::FAILURE;
        }
        
        $io->title('PHPMailer SMTP Test');
        $io->section('SMTP Configuration');
        $io->definitionList(
            ['Host' => $host],
            ['Port' => $port],
            ['Username' => $username ?: 'None'],
            ['Authentication' => ($username && $password) ? 'Yes' : 'No'],
            ['TLS' => $useTls ? 'Yes (STARTTLS)' : 'No'],
            ['SSL' => $useSsl ? 'Yes (Direct SSL)' : 'No'],
            ['Verify SSL' => $noVerifySsl ? 'No' : 'Yes'],
            ['Debug Level' => $debugLevel]
        );
        
        $io->section('Email Settings');
        $io->definitionList(
            ['From' => ($fromName ? "$fromName <$from>" : $from)],
            ['To' => ($toName ? "$toName <$to>" : $to)],
            ['Subject' => $subject]
        );
        
        try {
            // Create a new PHPMailer instance
            $io->text('Creating PHPMailer instance...');
            $mail = new PHPMailer(true);
            
            // Set debug level
            $mail->SMTPDebug = $debugLevel;
            $mail->Debugoutput = function($str, $level) use ($io) {
                $io->text("<fg=gray>[$level] $str</>");
            };
            
            // Set up SMTP
            $io->text('Setting up SMTP connection...');
            $mail->isSMTP();
            $mail->Host = $host;
            $mail->Port = $port;
            
            // Set authentication if username and password are provided
            if ($username) {
                $mail->SMTPAuth = true;
                $mail->Username = $username;
                if ($password) {
                    $mail->Password = $password;
                }
            } else {
                $mail->SMTPAuth = false;
            }
            
            // Set TLS/SSL options
            if ($useSsl) {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // SSL/TLS
            } elseif ($useTls) {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // STARTTLS
            } else {
                $mail->SMTPSecure = ''; // No encryption
                $mail->SMTPAutoTLS = false; // Disable auto TLS
            }
            
            // Set SSL verification
            if ($noVerifySsl) {
                $mail->SMTPOptions = [
                    'ssl' => [
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                        'allow_self_signed' => true
                    ]
                ];
            }
            
            // Set message details
            $io->text('Setting up email content...');
            $mail->setFrom($from, $fromName);
            $mail->addAddress($to, $toName);
            $mail->Subject = $subject;
            $mail->isHTML(true);
            $mail->Body = $body;
            $mail->AltBody = strip_tags(str_replace(['<br>', '<br />', '<br/>'], "\n", $body));
            
            // Send the email
            $io->text('Sending email...');
            $mail->send();
            
            $io->success('Email sent successfully!');
            return Command::SUCCESS;
        } catch (Exception $e) {
            $io->error('Error sending email: ' . $mail->ErrorInfo);
            return Command::FAILURE;
        }
    }
}