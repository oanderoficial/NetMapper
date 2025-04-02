# NetMapper Documentação
Varredura Nmap gráfica. Detecta sistemas operacionais, portas e serviços ativos na rede.

## Bibliotecas utilizadas no projeto

<strong> Gradio </strong>: https://www.gradio.app
<br>
<strong> python-nmap: </strong> https://pypi.org/project/python-nmap
<br>
<strong> networkx: </strong> https://networkx.org
<br> 
<strong>matplotlib: </strong> https://matplotlib.org/
<br>
<strong> pandas: </strong> https://pandas.pydata.org
<br>
<strong> Minimal DOM implementation: </strong> https://docs.python.org/pt-br/3.13/library/xml.dom.minidom.html

```python
import gradio as gr
import nmap
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import os
import platform
import xml.dom.minidom  # Biblioteca para formatar XML
```

## Verificar se o script está rodando como root (Linux/macOS)

```python
executando_com_root = False
if platform.system() != "Windows":
    executando_com_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
```

## Variável global para controle do scan 

```python
escaneamento_em_andamento = False
```

## Função para formatar a saída XML do Nmap para exibição legível

```python
def formatar_saida_nmap(saida_bruta):
    """Formata a saída XML do Nmap para exibição legível."""
    try:
        saida_bruta = saida_bruta.decode("utf-8") if isinstance(saida_bruta, bytes) else saida_bruta
        saida_xml = xml.dom.minidom.parseString(saida_bruta)
        saida_formatada = saida_xml.toprettyxml(indent="  ")
        return saida_formatada
    except Exception:
        return "Erro ao formatar saída do Nmap."
```

## Função que executa o scan Nmap 

```python 
def escanear_rede(alvo, portas, tipo_escaneamento):
    """Executa o scan do Nmap e retorna os resultados formatados."""
    global escaneamento_em_andamento
    escaneamento_em_andamento = True

    if not executando_com_root and tipo_escaneamento in ["-sS", "-A"]:
        return "Erro: Este tipo de scan requer privilégios de root. Execute com `sudo`.", None, None, None

    try:
        scanner = nmap.PortScanner()
    except AttributeError:
        return "Erro: Biblioteca `python-nmap` não instalada corretamente!", None, None, None

    try:
        # Se o usuário não informar portas, não passamos o argumento
        if portas.strip():
            scanner.scan(alvo, portas, tipo_escaneamento)  # Usa as portas fornecidas
        else:
            scanner.scan(alvo, arguments=tipo_escaneamento)  # Usa o scan padrão do Nmap

        if not scanner.all_hosts():
            return "Nenhum host encontrado. Verifique o IP e as configurações.", None, None, None

        resultados = []
        mapa_rede = nx.Graph()

        for host in scanner.all_hosts():
            if not escaneamento_em_andamento:
                return "Escaneamento interrompido!", None, None, None

            sistema_operacional = scanner[host].get('osclass', [{"osfamily": "Desconhecido"}])[0].get('osfamily', "Desconhecido")
            for protocolo in scanner[host].all_protocols():
                for porta in scanner[host][protocolo]:
                    estado = scanner[host][protocolo][porta]["state"]
                    servico = scanner[host][protocolo][porta].get("name", "Desconhecido")
                    
                    resultados.append({
                        "Host": host,
                        "Sistema Operacional": sistema_operacional,
                        "Protocolo": protocolo,
                        "Porta": porta,
                        "Serviço": servico,
                        "Estado": estado
                    })

                    mapa_rede.add_node(host)
                    mapa_rede.add_edge(host, f"Porta {porta} ({servico})")

        if not resultados:
            return "Nenhum resultado encontrado. O scan pode ter sido bloqueado pelo firewall.", None, None, None

        df_resultados = pd.DataFrame(resultados)

        # Criar e exibir o mapa de rede
        caminho_imagem = "mapa_rede.png"
        plt.figure(figsize=(10, 6))
        nx.draw(mapa_rede, with_labels=True, node_color='lightblue', edge_color='gray')
        plt.title("Mapa de Rede")
        plt.savefig(caminho_imagem)
        plt.close()

        # Obtém a saída completa do comando Nmap e formata
        saida_bruta = scanner.get_nmap_last_output()
        saida_formatada = formatar_saida_nmap(saida_bruta)

        return df_resultados, caminho_imagem, "Escaneamento concluído!", saida_formatada

    except Exception as e:
        return f"Erro ao escanear: {str(e)}", None, None, None
```

## Função para interromper o scan

```python
def parar_escaneamento():
    """Interrompe o escaneamento"""
    global escaneamento_em_andamento
    escaneamento_em_andamento = False
    return "Escaneamento interrompido pelo usuário!"
```

## Frontend

```css
estilo_css = """
footer {display: none !important;}

/* Rodapé fixo personalizado */
.custom-footer {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    background-color: #222;
    color: white;
    text-align: center;
    padding: 10px 0;
    font-size: 14px;
    font-family: Arial, sans-serif;
}


/* Estiliza o link do GitHub */
.custom-footer a {
    color: #007bff;
    text-decoration: none;
    font-weight: bold;
}
.custom-footer a:hover {
    text-decoration: underline;
}
""
```

## HTML do footer 

```html
custom_footer = """
<div class="custom-footer">
    Desenvolvido por Anderson Bezerra Silva | 
    <a href="https://github.com/oanderoficial" target="_blank">GitHub</a>
</div>
"""
```

## Criar interface Gradio

```python
with gr.Blocks(css=estilo_css) as interface:
    gr.Markdown("## **NetMapper - Scanner Nmap Gráfico**")
    gr.Markdown(" **Varredura Nmap gráfica.** Detecta sistemas operacionais, portas e serviços ativos na rede.")

    with gr.Row():
        alvo = gr.Textbox(label="Endereço IP ou Faixa de IPs", placeholder="Ex: 192.168.1.1 ou 192.168.1.0/24")
        portas = gr.Textbox(label="Portas (opcional)", placeholder="Ex: 22,80,443 (ou deixe em branco para scan padrão)")
    
    tipo_escaneamento = gr.Radio(["-sS", "-sT", "-sU", "-sV", "-A", "-sC"], label="Tipo de Escaneamento", value="-sS")

    botao_escanear = gr.Button("Iniciar Escaneamento")
    botao_parar = gr.Button("Parar Escaneamento")
    
    tabela_resultados = gr.Dataframe()
    imagem_mapa = gr.Image(type="filepath", label="Mapa da Rede")
    mensagem_status = gr.Textbox(label="Status", interactive=False)
    saida_nmap = gr.Textbox(label="Saída Completa do Nmap", interactive=False, lines=20)

    botao_escanear.click(fn=escanear_rede, inputs=[alvo, portas, tipo_escaneamento], outputs=[tabela_resultados, imagem_mapa, mensagem_status, saida_nmap])
    botao_parar.click(fn=parar_escaneamento, inputs=[], outputs=[mensagem_status])

    # Adiciona o Footer na Interface
    gr.Markdown(custom_footer)

interface.launch(share=False, show_api=False, server_name="0.0.0.0", server_port=7860)

```
