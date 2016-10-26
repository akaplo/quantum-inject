# quantum-inject and quantum-detect

### This project is in a MOSTLY working state. It does all that should be expected EXCEPT that browsers won't display the injected responses from quantum-inject.py.  Use at your own risk.

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
