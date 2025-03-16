<?php

namespace App\Command;

use App\Service\SmtpServerService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:smtp:start',
    description: 'Start the SMTP server',
)]
class StartSmtpServerCommand extends Command
{
    private SmtpServerService $smtpServer;

    public function __construct(SmtpServerService $smtpServer)
    {
        parent::__construct();
        $this->smtpServer = $smtpServer;
    }

    protected function configure(): void
    {
        $this
            ->addOption('port', 'p', InputOption::VALUE_OPTIONAL, 'Port to listen on', 25)
            ->addOption('host', null, InputOption::VALUE_OPTIONAL, 'Host to bind to', '0.0.0.0')
            ->addOption('timeout', 't', InputOption::VALUE_OPTIONAL, 'Connection timeout in seconds', 30)
            ->addOption('max-connections', 'm', InputOption::VALUE_OPTIONAL, 'Maximum number of simultaneous connections', 10)
            ->addOption('debug', 'd', InputOption::VALUE_OPTIONAL, 'Debug level (0-3)', 1)
            ->addOption('tls', null, InputOption::VALUE_OPTIONAL, 'Enable TLS support (0=disabled, 1=enabled)', 1)
            ->addOption('tls-cert', null, InputOption::VALUE_OPTIONAL, 'Path to TLS certificate file', __DIR__ . '/../../var/certs/certificate.crt')
            ->addOption('tls-key', null, InputOption::VALUE_OPTIONAL, 'Path to TLS key file', __DIR__ . '/../../var/certs/private.key')
            ->addOption('tls-passphrase', null, InputOption::VALUE_OPTIONAL, 'TLS certificate passphrase if needed');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $config = [
            'port' => (int) $input->getOption('port'),
            'host' => $input->getOption('host'),
            'timeout' => (int) $input->getOption('timeout'),
            'maxConnections' => (int) $input->getOption('max-connections'),
            'debug' => (int) $input->getOption('debug'),
            'tls_enabled' => (bool) (int) $input->getOption('tls'),
            'tls_cert_file' => $input->getOption('tls-cert'),
            'tls_key_file' => $input->getOption('tls-key'),
            'tls_passphrase' => $input->getOption('tls-passphrase'),
        ];
        
        // Set the output for direct console logging
        $this->smtpServer->setOutput($output);
        
        $io->title('MailHarbor SMTP Server');
        $io->text([
            'Starting SMTP server on ' . $config['host'] . ':' . $config['port'],
        ]);

        if ($this->smtpServer->start($config)) {
            $io->text([
                'SMTP server started successfully, listenning...',
                'Press Ctrl+C to stop the server',
                null,
            ]);

            // Set up signal handling for graceful shutdown
            pcntl_async_signals(true);
            pcntl_signal(SIGINT, function () use ($io) {
                $io->note('Shutting down SMTP server...');
                $this->smtpServer->stop();
                $io->success('SMTP server stopped successfully');
                exit(0);
            });
            
            // Keep the command running until stopped
            while ($this->smtpServer->isRunning()) {
                // Process incoming connections and client data
                $this->smtpServer->processConnections();
                
                // Small delay to prevent CPU usage spike
                usleep(10000); // 10ms
            }
            
            return Command::SUCCESS;
        }
        
        $io->error('Failed to start SMTP server');
        return Command::FAILURE;
    }
}
