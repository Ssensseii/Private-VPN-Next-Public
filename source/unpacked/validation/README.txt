Проверка конфигураций PrivateVPN Next на Windows
================================================

Эти файлы только для команды sing-box check. Не используйте их для подключения:
proxy.example.net и примерный путь Chrome — демонстрационные значения.

Скопируйте JSON-файлы в C:\PrivateVPN-Next\core либо оставьте в validation и
запустите PowerShell в папке core:

  .\sing-box.exe check -c ..\validation\config_next_validation.json
  $LASTEXITCODE

  .\sing-box.exe check -c ..\validation\config_next_accel_validation.json
  $LASTEXITCODE

  .\sing-box.exe check -c ..\validation\config_next_http_validation.json
  $LASTEXITCODE

  .\sing-box.exe check -c ..\validation\config_next_http_accel_validation.json
  $LASTEXITCODE

Ожидается 0 для всех четырёх файлов. Проверяется синтаксис sing-box 1.14.4,
включая process_path, IPv4-only DNS для проксируемых запросов и прямой маршрут
к IP/порту самого прокси, чтобы исключить петлю TUN.
VPN перезапускать не нужно. Эти команды не запускают конфигурацию.
