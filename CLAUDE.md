# MailHarbor Project Guide

## Build, Lint & Test Commands
- Start project: `symfony server:start`
- Run tests: `php bin/phpunit`
- Run single test: `php bin/phpunit tests/Path/To/TestFile.php`
- Check syntax: `php -l src/path/to/file.php`
- Code quality: `vendor/bin/phpstan analyse src`
- Run console command: `php bin/console <command-name>`

## Code Style Guidelines
- **PHP Version**: 8.2+
- **Namespaces**: Use `App\` namespace prefix
- **PSR Standards**: Follow PSR-1, PSR-12, PSR-4
- **Type Hinting**: Use strict typing with return types and parameter types
- **Naming**: 
  - Classes: PascalCase
  - Methods/Functions: camelCase
  - Properties: camelCase
  - Constants: UPPERCASE_WITH_UNDERSCORES
- **Error Handling**: Use exceptions with proper hierarchy
- **Imports**: Group in order: PHP core, 3rd party libs, App namespaces
- **Documentation**: PHPDoc blocks for classes and methods

## Project Organization
- SMTP server implementation using Symfony Console commands
- Email storage using filesystem-based approach (.eml files)
- Follow Symfony best practices for controller/service organization