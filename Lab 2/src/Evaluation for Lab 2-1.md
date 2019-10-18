# Evaluation for Lab 2-1

- `$ make` to get the execution file `main`
- Put the `main` file under the `vnetutils/helper` folder
- Create network namespace and virtual ethernet pairs using the `makeNet` script given in the `examples` folder (suppose the ns name is 'LABns1', 'LABns2'...)
- `$ sudo ./execNS LABns1 ./main` and `$ sudo ./execNS LABns2 ./main`in 2 different terminals(Suppose ns1 and ns2 have connections)
- In the first terminal, input `addDevice LABveth1-2`; in the second terminal, input `addDevice LABveth2-1` to add device. And now we can see the MAC address of both devices in the terminal.
- Input `send LABveth1-2 MAC-addr-of-ns2 hello`, we can now see the message received by the second terminal. 