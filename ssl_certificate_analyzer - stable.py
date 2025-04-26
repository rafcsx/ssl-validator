import os
import sys
import time
import threading
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import requests
from colorama import init, Fore, Back, Style
import textwrap
import re
import logging
from datetime import datetime
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', message="urllib3 .* doesn't match a supported version")
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Configuração básica de logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='ssl_tester.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

# Inicializa colorama
init(autoreset=True)

# Cores personalizadas
CYAN = Fore.CYAN
GRAY = Fore.LIGHTBLACK_EX
WHITE = Fore.WHITE
RED = Fore.RED
DARK_RED = Fore.LIGHTRED_EX
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW

# =============================================
# UTILITÁRIOS DE INTERFACE
# =============================================
def clear_screen():
    """Limpa a tela do console"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Exibe o cabeçalho animado"""
    clear_screen()
    print(CYAN + r"""
""")
    
    print(WHITE + textwrap.dedent(r"""
               ,---------------------------,
               |  /---------------------\  |
               | |                       | |
               | |    SSL Validator      | |
               | |                       | |
               | |  rafcsx - fullstack   | |
               | |  v2.0.1  | SSL Tools  | |
               | |                       | |
               |  \_____________________/  |
               |___________________________|
             ,---\_____     []     _______/------,
           /         /______________\           /|
         /___________________________________ /  | ___
         |                                   |   |    )
         |  _ _ _                 [-------]  |   |   (
         |  o o o                 [-------]  |  /    _)_
         |__________________________________ |/     /  /
     /-------------------------------------/|      ( )/
   /-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /
 /-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"""))

def typewriter_effect(text: str, color=WHITE, delay=0.03):
    """Efeito máquina de escrever"""
    for char in text:
        sys.stdout.write(color + char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def animate_border(message: str, width=50, color=CYAN):
    """Cria uma borda animada ao redor da mensagem"""
    border = '=' * width
    centered_msg = message.center(width, ' ')
    print(color + border)
    typewriter_effect(color + centered_msg, delay=0.01)
    print(color + border)

def loading_spinner(message: str, duration=2):
    """Mostra uma animação de carregamento"""
    phases = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    start_time = time.time()
    
    while time.time() - start_time < duration:
        for phase in phases:
            sys.stdout.write(f"\r{CYAN}{phase} {WHITE}{message}... {GRAY}{int((time.time() - start_time)/duration*100)}%")
            sys.stdout.flush()
            time.sleep(0.1)
    print()

# Handler HTTP personalizado para o teste SSL
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'SSL Test Server - Connection Successful')

# =============================================
# CORE SSL TESTER
# =============================================
class SSLTest:
    def __init__(self):
        self.cert_content = ""
        self.key_content = ""
        self.use_temp_files = False
        self.start_time = datetime.now()
        logger.info(f"Iniciando nova sessão de testes em {self.start_time}")

    def log_error(self, error_type: str, message: str, details: str = ""):
        """Registra erros de forma consistente"""
        error_msg = f"[{error_type}] {message}"
        if details:
            error_msg += f"\nDetalhes: {details}"
        
        logger.error(error_msg)
        print(f"{RED}[!] {error_type}: {message}")
        if details:
            print(f"{YELLOW}Detalhes: {WHITE}{details}")

    def sanitize_pem_content(self, content: str, pem_type: str) -> str:
        """Remove caracteres inválidos e formata corretamente o PEM"""
        try:
            # Remove espaços no início/fim e quebras de linha extras
            content = content.strip()
            
            # Garante que BEGIN/END estão em linhas separadas
            begin_marker = f"-----BEGIN {pem_type}-----"
            end_marker = f"-----END {pem_type}-----"
            
            if not content.startswith(begin_marker):
                content = begin_marker + "\n" + content
            if not content.endswith(end_marker):
                content = content + "\n" + end_marker
                
            # Remove linhas vazias e espaços extras
            lines = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    lines.append(line)
            
            # Garante formato PEM válido
            if len(lines) < 3:
                raise ValueError(f"Conteúdo PEM inválido para {pem_type} - muito curto")
                
            return "\n".join(lines) + "\n"
            
        except Exception as e:
            self.log_error("ERRO DE FORMATO", f"Problema ao sanitizar conteúdo {pem_type}", str(e))
            raise

    def get_certificate_input(self, cert_type: str):
        """Obtém entrada do certificado ou chave privada com validação robusta"""
        print(f"\n{CYAN}Por favor, cole seu {cert_type} completo (incluindo BEGIN/END):")
        print(f"{GRAY}-----BEGIN {cert_type}-----")
        print(f"{GRAY}[Cole aqui o conteúdo entre as linhas BEGIN/END]")
        print(f"{GRAY}-----END {cert_type}-----")
        print(f"{WHITE}Cole o conteúdo completo abaixo (incluindo BEGIN/END):\n")
        
        lines = []
        while True:
            try:
                line = input()
                if not line.strip() and len(lines) > 0:  # Finaliza com linha em branco
                    break
                lines.append(line)
            except EOFError:
                break
            except Exception as e:
                self.log_error("ERRO DE ENTRADA", "Falha ao ler entrada do usuário", str(e))
                continue
        
        content = '\n'.join(lines)
        
        try:
            # Sanitiza e valida o conteúdo PEM
            sanitized = self.sanitize_pem_content(content, cert_type)
            
            # Verificação adicional para chaves privadas
            if cert_type == "PRIVATE KEY":
                if "ENCRYPTED" in sanitized:
                    raise ValueError("Chaves privadas criptografadas não são suportadas")
                if not re.search(r"-----BEGIN PRIVATE KEY-----\n.*\n-----END PRIVATE KEY-----", sanitized, re.DOTALL):
                    raise ValueError("Formato de chave privada inválido")
            
            logger.info(f"Conteúdo {cert_type} recebido e validado com sucesso")
            return sanitized
            
        except ValueError as e:
            self.log_error("ERRO DE VALIDAÇÃO", f"Problema no formato {cert_type}", str(e))
            print(f"{YELLOW}Por favor, cole novamente o conteúdo completo...")
            return self.get_certificate_input(cert_type)
        except Exception as e:
            self.log_error("ERRO INESPERADO", f"Falha ao processar {cert_type}", str(e))
            raise

    def get_user_input(self):
        """Obtém as chaves SSL do usuário com UX melhorada"""
        animate_border(" INSIRA SUAS CHAVES SSL ")
        
        try:
            # Certificado
            self.cert_content = self.get_certificate_input("CERTIFICATE")
            
            # Chave privada
            self.key_content = self.get_certificate_input("PRIVATE KEY")
            
            # Opção de arquivos temporários
            print()
            loading_spinner("Processando entrada")
            print(f"\n{WHITE}Modo de operação: {GREEN}Memória temporária{WHITE} (recomendado)")
            print(f"{WHITE}Deseja gerar arquivos físicos para inspeção manual? {GRAY}(S/N): {WHITE}", end="")
            self.use_temp_files = input().strip().upper() == "S"
            
            logger.info(f"Modo de operação selecionado: {'Arquivos físicos' if self.use_temp_files else 'Memória temporária'}")
            
        except Exception as e:
            self.log_error("ERRO FATAL", "Falha crítica ao obter entrada do usuário", str(e))
            raise

    def validate_certificates(self) -> bool:
        """Valida os certificados com tratamento robusto"""
        animate_border(" VALIDANDO CERTIFICADOS ")
        logger.info("Iniciando validação de certificados")
        
        # Verificação básica de formato
        errors = []
        
        if not self.cert_content.startswith("-----BEGIN CERTIFICATE-----"):
            errors.append("Certificado deve começar com '-----BEGIN CERTIFICATE-----'")
            
        if not self.cert_content.endswith("-----END CERTIFICATE-----\n"):
            errors.append("Certificado deve terminar com '-----END CERTIFICATE-----'")
            
        if "PRIVATE KEY" in self.cert_content:
            errors.append("Certificado não deve conter chave privada")
            
        if not self.key_content.startswith("-----BEGIN PRIVATE KEY-----"):
            errors.append("Chave deve começar com '-----BEGIN PRIVATE KEY-----'")
            
        if not self.key_content.endswith("-----END PRIVATE KEY-----\n"):
            errors.append("Chave deve terminar com '-----END PRIVATE KEY-----'")
            
        if "CERTIFICATE" in self.key_content:
            errors.append("Chave privada não deve conter certificado")
        
        if errors:
            for error in errors:
                logger.error(f"Erro de validação: {error}")
                print(f"{RED}[X] {error}")
            print(f"\n{RED}*** CORRIJA OS PROBLEMAS ACIMA E TENTE NOVAMENTE ***")
            return False
        
        # Validação avançada usando OpenSSL
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as cert_file, \
                 tempfile.NamedTemporaryFile(mode='w+', delete=False) as key_file:
                
                logger.debug("Criando arquivos temporários para validação")
                cert_file.write(self.cert_content)
                key_file.write(self.key_content)
                cert_file.flush()
                key_file.flush()
                
                # Verificação do certificado
                logger.debug("Validando estrutura do certificado")
                try:
                    cert = ssl._ssl._test_decode_cert(cert_file.name)
                    if not cert:
                        raise ValueError("Falha ao decodificar certificado - estrutura inválida")
                except AttributeError:
                    # Fallback para versões mais recentes do Python
                    cert = ssl._ssl._test_decode_certificate(cert_file.name)
                    if not cert:
                        raise ValueError("Falha ao decodificar certificado - estrutura inválida")
                
                # Validação de datas
                logger.debug("Verificando datas de validade")
                not_before = ssl.cert_time_to_seconds(cert['notBefore'])
                not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                current_time = time.time()
                
                if current_time < not_before:
                    raise ValueError(f"Certificado ainda não válido (válido a partir de {cert['notBefore']})")
                
                if current_time > not_after:
                    raise ValueError(f"Certificado expirado (expirou em {cert['notAfter']})")
                
                # Tenta criar um contexto SSL com o par
                logger.debug("Validando par certificado/chave")
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                
                # Verificação adicional do subject/issuer
                logger.debug("Verificando subject/issuer")
                if 'subject' not in cert or not cert['subject']:
                    logger.warning("Certificado sem subject definido")
                
                if 'issuer' not in cert or not cert['issuer']:
                    logger.warning("Certificado sem issuer definido")
                
            logger.info("Certificados validados com sucesso")
            print(f"{GREEN}[✓] Certificados validados com sucesso!")
            print(f"{WHITE}Detalhes do certificado:")
            print(f"- Válido de: {CYAN}{cert['notBefore']} {WHITE}até: {CYAN}{cert['notAfter']}")
            print(f"- Subject: {CYAN}{cert.get('subject', 'N/A')}")
            print(f"- Issuer: {CYAN}{cert.get('issuer', 'N/A')}")
            
            # Remove os arquivos temporários após uso
            try:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)
            except Exception as e:
                logger.warning(f"Erro ao remover arquivos temporários: {str(e)}")
            
            return True
            
        except ssl.SSLError as e:
            error_details = f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
            if hasattr(e, 'reason'):
                error_details += f"\nReason: {e.reason}"
            
            self.log_error(
                "ERRO SSL", 
                "Falha na validação SSL", 
                error_details
            )
            print(f"{YELLOW}Possíveis causas:")
            print(f"{YELLOW}1. Chave privada não corresponde ao certificado")
            print(f"{YELLOW}2. Certificado expirado ou inválido")
            print(f"{YELLOW}3. Problema no formato dos arquivos")
            return False
            
        except Exception as e:
            self.log_error(
                "ERRO DE VALIDAÇÃO", 
                "Falha inesperada na validação", 
                f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
            )
            return False

    def test_ssl_connection(self) -> bool:
        """Testa a conexão SSL com tratamento de erros completo"""
        animate_border(" TESTANDO CONEXÃO SSL ")
        logger.info("Iniciando teste de conexão SSL")
        
        cert_path = key_path = server = None
        success = False
        connection_details = {}
        
        try:
            # Cria arquivos temporários
            if self.use_temp_files:
                loading_spinner("Criando ambiente de teste")
                os.makedirs("tmp", exist_ok=True)
                
                cert_path = "tmp/certificate.pem"
                key_path = "tmp/private.key"
                
                with open(cert_path, "w") as f:
                    f.write(self.cert_content)
                with open(key_path, "w") as f:
                    f.write(self.key_content)
            else:
                cert_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                cert_file.write(self.cert_content)
                cert_path = cert_file.name
                cert_file.close()
                
                key_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                key_file.write(self.key_content)
                key_path = key_file.name
                key_file.close()
            
            # Configura servidor HTTPS
            loading_spinner("Iniciando servidor de teste")
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
            # Configuração mais tolerante para testes
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            # Configuração de protocolos e cifras
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5')
            
            server = HTTPServer(('localhost', 8443), SimpleHTTPRequestHandler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            
            # Inicia servidor em thread
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            
            # Testa conexão com configuração mais tolerante
            loading_spinner("Testando conexão SSL/TLS")
            try:
                session = requests.Session()
                adapter = requests.adapters.HTTPAdapter(
                    max_retries=3,
                    pool_connections=1,
                    pool_maxsize=1
                )
                session.mount('https://', adapter)
                
                response = session.get(
                    "https://localhost:8443",
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    # Tenta obter informações da conexão de forma mais segura
                    try:
                        conn = response.connection
                        if conn and hasattr(conn, 'sock'):
                            cipher = conn.sock.cipher()
                            connection_details = {
                                'protocol': getattr(response.raw, 'version', 'N/A'),
                                'cipher_suite': cipher[0] if cipher else 'N/A',
                                'ssl_version': cipher[1] if cipher else 'N/A',
                                'security_bits': cipher[2] if cipher else 'N/A'
                            }
                            print(f"{GREEN}[✓] Conexão SSL estabelecida com sucesso!")
                            print(f"{WHITE}Detalhes:")
                            print(f"- Protocolo: {CYAN}{connection_details.get('protocol', 'N/A')}")
                            print(f"- Cipher Suite: {CYAN}{connection_details.get('cipher_suite', 'N/A')}")
                            print(f"- Versão SSL: {CYAN}{connection_details.get('ssl_version', 'N/A')}")
                            print(f"- Bits de segurança: {CYAN}{connection_details.get('security_bits', 'N/A')}")
                            success = True
                        else:
                            print(f"{GREEN}[✓] Conexão estabelecida mas não foi possível obter detalhes SSL")
                            success = True
                    except Exception as conn_error:
                        logger.warning(f"Erro ao obter detalhes da conexão: {str(conn_error)}")
                        print(f"{GREEN}[✓] Conexão estabelecida mas com limitações na coleta de informações")
                        success = True
                else:
                    print(f"{YELLOW}[!] Conexão estabelecida mas retornou status {response.status_code}")
                    success = False
                    
            except requests.exceptions.SSLError as e:
                self.log_error(
                    "FALHA SSL", 
                    "Erro na negociação SSL", 
                    f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
                )
                print(f"{YELLOW}Possíveis causas:")
                print(f"{YELLOW}1. Chave privada não corresponde ao certificado")
                print(f"{YELLOW}2. Certificado expirado ou inválido")
                print(f"{YELLOW}3. Problema no formato dos arquivos")
                success = False
                
            except requests.exceptions.RequestException as e:
                self.log_error(
                    "ERRO DE CONEXÃO", 
                    "Falha na requisição HTTPS", 
                    f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
                )
                success = False
                
        except ssl.SSLError as e:
            self.log_error(
                "ERRO SSL SERVIDOR", 
                "Falha ao configurar servidor SSL", 
                f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
            )
            success = False
            
        except Exception as e:
            self.log_error(
                "ERRO CRÍTICO", 
                "Falha inesperada no teste SSL", 
                f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
            )
            success = False
            
        finally:
            try:
                if server:
                    server.shutdown()
                    server.server_close()
                
                if not self.use_temp_files:
                    if cert_path and os.path.exists(cert_path):
                        os.unlink(cert_path)
                    if key_path and os.path.exists(key_path):
                        os.unlink(key_path)
            except Exception as e:
                self.log_error("ERRO DE LIMPEZA", "Falha ao limpar recursos", str(e))
        
        return success

    def run_tests(self):
        """Fluxo principal de execução"""
        try:
            print_header()
            logger.info("Iniciando fluxo principal de testes")
            
            # Fase 1: Entrada de dados
            self.get_user_input()
            
            # Fase 2: Validação
            if not self.validate_certificates():
                raise ValueError("Validação de certificados falhou")
            
            # Fase 3: Teste
            if self.test_ssl_connection():
                # Sucesso
                logger.info("Teste SSL concluído com sucesso")
                print(f"{GREEN}\n" + "="*50)
                print(f"{YELLOW} SSL CONFIGURADO CORRETAMENTE! ".center(50))
                print(f"{GREEN}" + "="*50)
                
                print(f"{DARK_RED}" + textwrap.dedent(r"""
                            ,-.                               
                   ___,---.__          /'|`\          __,---,___          
                ,-'    \`    `-.____,-'  |  `-.____,-'    //    `-.       
              ,'        |           ~'\     /`~           |        `.      
             /      ___//              `. ,'          ,  , \___      \    
            |    ,-'   `-.__   _         |        ,    __,-'   `-.    |    
            |   /          /\_  `   .    |    ,      _/\          \   |   
            \  |           \ \`-.___ \   |   / ___,-'/ /           |  /  
             \  \           | `._   `\\  |  //'   _,' |           /  /      
              `-.\         /'  _ `---'' , . ``---' _  `\         /,-'     
                 ``       /     \    ,='/ \`=.    /     \       ''          
                         |__   /|\_,--.,-.--,--._/|\   __|                  
                         /  `./  \\`\ |  |  | /,//' \,'  \                  
                        /   /     ||--+--|--+-/-|     \   \                 
                       |   |     /'\_\_\ | /_/_/`\     |   |                
                        \   \__, \_     `~'     _/ .__/   /            
                         `-._,-'   `-._______,-'   `-._,-'
                         github.com/rafcsx"""))
            else:
                # Falha
                logger.warning("Teste SSL falhou")
                print(f"{RED}\n" + "="*50)
                print(f"{YELLOW} PROBLEMAS NA CONFIGURAÇÃO SSL ".center(50))
                print(f"{RED}" + "="*50)
                print(f"{YELLOW}\nRecomendações:")
                print("- Verifique se a chave privada corresponde ao certificado")
                print("- Confira as datas de validade dos certificados")
                print("- Valide a cadeia de certificados completa")
                print("- Verifique se o certificado inclui todos os intermediários")
                print("- Teste com diferentes protocolos (TLS 1.2/1.3)")
                
        except KeyboardInterrupt:
            print(f"\n{RED}Operação cancelada pelo usuário")
            logger.warning("Operação cancelada pelo usuário")
        except Exception as e:
            self.log_error(
                "ERRO NO FLUXO", 
                "Falha durante a execução dos testes", 
                f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
            )
        finally:
            # Encerramento
            duration = datetime.now() - self.start_time
            logger.info(f"Sessão finalizada. Duração: {duration}")
            print(f"\n{WHITE}Teste concluído em {duration.total_seconds():.2f} segundos")
            print(f"{WHITE}Logs detalhados disponíveis em: ssl_tester.log")
            print(f"{WHITE}\nPressione Enter para sair..." + Style.RESET_ALL)
            input()

if __name__ == "__main__":
    try:
        tester = SSLTest()
        tester.run_tests()
    except Exception as e:
        print(f"\n{RED}ERRO CRÍTICO: O programa encontrou um erro inesperado e será encerrado")
        print(f"{YELLOW}Detalhes do erro: {str(e)}")
        print(f"{WHITE}Verifique o arquivo ssl_tester.log para mais informações")
        input("Pressione Enter para sair...")
