# NetMapper
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
