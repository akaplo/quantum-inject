# quantum-inject and quantum-detect

## Instructions to install dependencies
1. _scapy_ - Visit http://secdev.org/projects/scapy/doc/installation.html and follow instructions for **scapy 2.x**


## Usages:
- Injector:

    ``` bash
    python quantum-inject.py -i network_interface -r regex -d filepath filter_expression
    ```
    **filter_expression MUST be surrounded by quotation marks**

- Detector:

    ``` bash
      python quantum-detect.py -i network_interface -r filepath filter_expression
    ```
    **filter_expression MUST be surrounded by quotation marks**
