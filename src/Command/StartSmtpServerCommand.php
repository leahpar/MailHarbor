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
            ->addOption('max-connections', 'm', InputOption::VALUE_OPTIONAL, 'Maximum number of simultaneous connections', 10);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $config = [
            'port' => (int) $input->getOption('port'),
            'host' => $input->getOption('host'),
            'timeout' => (int) $input->getOption('timeout'),
            'maxConnections' => (int) $input->getOption('max-connections'),
        ];
        
        $io->title('MailHarbor SMTP Server');
        $io->text([
            'Starting SMTP server on ' . $config['host'] . ':' . $config['port'],
            'Press Ctrl+C to stop the server',
        ]);

        if ($this->smtpServer->start($config)) {
            $io->success('SMTP server started successfully');
            
            // This will be replaced with an event loop to keep the command running
            while ($this->smtpServer->isRunning()) {
                // Simple placeholder for the actual implementation
                sleep(1);
            }
            
            return Command::SUCCESS;
        }
        
        $io->error('Failed to start SMTP server');
        return Command::FAILURE;
    }
}