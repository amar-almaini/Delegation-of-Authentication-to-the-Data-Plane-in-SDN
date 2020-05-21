# Portknocking

## Introduction

This P4 Program is designed to be a simple solution for Portknocking. You´ll find implementations for P4_14 and P4_16.
The Switch will wait for the "knocks" to a combination of three specific ports, these ports are defined through our rules.

The rules necessary for this are:

````
table_add update_state_table update_state 5100 0 => 1 0
table_add update_state_table update_state 5150 1 => 2 0
table_add update_state_table update_state 5155 2 => 3 1
````

In this case the knocks are for port `5100`, `5150` and `5155` in this specific order after the third correct portknock a ticket will be granted and the connection will be successfull.

The knocks are provided by a simple scapy program called `knock.py`.

The blocked route is also added through the rules into the `ticket_deny_table`

```
table_add ticket_deny_table _nop 0 10.0.1.10/32 10.0.3.10 =>
```

In this case no connection will be possible from 10.0.1.10 to 10.0.3.10

## How to run this program
![tutorial](https://mygit.th-deg.de/tk12797/portknock/-/raw/master/img/tutorial.gif)


#### 1. Step: Compiling the P4-program

  Depending on the version the commands to compile the code are diffrent:
  *  P4_14
  ````
  p4c-bm2-ss --std p4-14 output.p4_14.p4 -o portknock.p4_14.json
  ````
  *  P4_16
  ````
  p4c-bm2-ss --std p4-16 output.p4_16.p4 -o portknock.p4_16.json
  ````

#### 2. Step: Starting Mininet with the corresponding json-file

  Depending on your setup the filepath might be different

  ```
  sudo python ~/p4/behavioral-model/mininet/1sw_demo.py  --behavioral-exe ~/p4/behavioral-model/targets/simple_switch/simple_switch --json portknock.p4_1X.json --num-hosts 4
  ```
  *please replace X with 4 or 6*

#### 3. Step: Adding rules to the switch

  In a new shell, run
  ```
  ~/p4/behavioral-model/tools/runtime_CLI.py < rules
  ```

  After these 3 Steps mininet and the switch are running with basic rules. A quick `pingall` should result in the following output:

  ![](https://mygit.th-deg.de/tk12797/portknock/-/raw/master/img/pingall.png)

#### 4. Step: Start a xterm and knock on the ports

  In the mininet start your h2 xterm
  ```
  xterm h2
  ```
  after that run in the freshly opend xterm `./knock.py`
