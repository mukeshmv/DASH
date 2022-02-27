---
title: Routing guidelines
last update: 02/28/2022
---

# Routing guidelines
- [Overview](#overview)
- [Routing examples](#routing-examples)
  - [Adding firewall hop to the routing table](#adding-firewall-hop-to-the-routing-table)
    - [Mapping](#mapping)
    - [RouteTable (LPM)](#routetable-lpm)
- [Terminlogy](#terminlogy)

## Overview

This article explains the basic steps to build a **routing table** (also knonw as *forwarding* table) and how to
use **mappings** during the process.  
It is important to notice from the get go, **routing** and **mapping** are two
different but complementary concepts, specifically:

1. **Routing**. It is used by the customer to configure the way the traffic must
be routed. It must be clear that routing table has the last say in the way the
traffic is routed. For example, by defaut usually this entry applies:

    `0/0 -> Internet (Default)`

    But the customer can override the entry and route the traffic as follows:

    `8.8.0.0/16 -> Internet (SNAT to VIP)`

    `0/0 -> Default Hop: 10.1.2.11 (Firewall in current VNET)`

1. **Mapping**. It allows to relate the customer’s defined routing to the
   network physical space that is transparent to the customer . In other words,
   mapping allows to know what is the **physical address** (PA) for a specific
   **customer address** (CA) and if it requires different encap, etc.
1. On the other hand, we want to be able to insert in the routing table
   any entry with a specific mapping, for example:  

    `10.3.0.0/16 -> VNET C (Peered) (use mapping)`

Notice that a routing table has a size limit of about 100 K while mapping has a
limit of 1 M. Using mapping allows you to extendd the amount of data that can be
contained in a routing table.

One of the main objectives of a routing table, more specifically **LPM
routing table**, is to allow the customers to enter static or mapped
entries the way they see fit. The LPM routing rules determine the order.
The rules can be either static or can refer to mapping. But mappings does not
control routing which is done via the LPM table.  

- **Static** means that when you create an entry into the table, you know exactly the physical address (PA).
  Here there is no mapping (lookup).
- **Mapping** means that for that particular entry, you want to intercept the traffic and exempt it from the standard routing.
Instead, you want to apply different actions than the ones associated with the rest of the traffic.

## Routing examples

This section provides guidelines, along with some examples, on how to build routing tables statically and/or by using mapping.

The following is an example of the kind of entries an LPM routing table may contain. We'll describe the various entries as we progess with the explantion.

```
VNET: 10.1.0.0/16
- Subnet 1: 10.1.1.0/24
- Subnet 2: 10.1.2.0/24  (VM/NVA: 10.1.2.11 - Firewall)
- Subnet 3: 10.1.3.0/24
- Mappings: 
 . VM 1: 10.1.1.1 (y)
 . VM 2: 10.1.3.2
 . Private Link 1: 10.1.3.3
 . Private Link 2: 10.1.3.4
 . VM 3: 10.1.3.5
 
ENIA_x - separate counter)
RouteTable (LPM)  attached to VM 10.1.1.1
- 10.1.0.0/16 -> VNET (use mappings)
 * route meter class: y
- 10.1.3.0/24 -> Hop: 10.1.2.11 Customer Address (CA) -> Private Address (PA) (Firewall in current VNET)
- 10.1.3.0/26 -> Hop: 10.1.2.88 Customer Address (CA) -> Private Address (PA)(Firewall in peered VNET)
 * route meter class: y
 * use mapping meter class (if exists): true
- 10.1.3.5/27 -> VNET A (mapping)
- 10.1.3.3/32 -> Private Link Route (Private Link 1)
- 10.2.0.0/16 -> VNET B (Peered) (use mapping)
 * route meter class: y
- 10.2.1.0/24 -> Hop: 10.1.2.11 Hop: 10.1.2.88(CA->PA) (Firewall in peered VNET)
- 10.2.0.0/16 -> VNET B (Peered) (use mappings)
 * route meter class: y
- 10.3.0.0/16 -> VNET C (Peered)  (use mappings)
 * route meter class: y
- 50.3.5.2/32 -> Private Link Route (Private Link 7)
 * route meter class: y
- 50.1.0.0/16 -> Internet
- 50.0.0.0/8 -> Hop: CISCO ER device PA (100.1.2.3, 10.1.2.4), GRE Key: X
- 8.8.0.0/16 -> Internet (SNAT to VIP)
- 0/0 -> Default Hop: 10.1.2.11 (Firewall in current VNET)

```

Notice a routing table is attached to a specific VM in the VNET, not to VNET itself. In VNET the VM functions like a router, to which a routing table is attached.

![dash-dataplane-routing-table-vm](./images/dash-dataplane-routing-table-vm.svg)

<figcaption><i>Figure 1. Routing table per VM</i></figcaption><br/>

### Adding firewall hop to the routing table

In the example shown below shows how to add a hop to a firewall in a routing table entry using mapping.  

#### Mapping

The `VNET: 10.1.0.0/16` has 3 subnets. A VM/NVA (VM or Virtual Appliance) firewall is added to Subnet 2 with address `10.1.2.11`.

```
VNET: 10.1.0.0/16

- Subnet 1: 10.1.1.0/24
- Subnet 2: 10.1.2.0/24 (VM/NVA: 10.1.2.11 - Firewall)
- Subnet 3: 10.1.3.0/24
```

#### RouteTable (LPM) 

A hop to the firewall (10.1.2.11) is added at address 10.1.3.0/24 

```
- 10.1.0.0/16 -> VNET
- 10.1.3.0/24 -> Hop: 10.1.2.11 (Firewall in current VNET)
- 10.2.0.0/16 -> VNET B (Peered) (use mappings)
- 10.3.0.0/16 -> VNET C (Peered) (use mappings)
- 0/0 -> Default (Internet)
```

The following settings should also be allowed:

```
- 10.1.0.0/16 -> VNET
- 10.1.3.0/24 -> Hop: 10.1.2.11 Customer Address (CA) -> Private Address (PA) (Firewall in current VNET)
- 10.1.3.0/26 -> Hop: 10.1.2.88 Customer Address (CA) -> Private Address (PA) (Firewall in peered VNET)
- 10.2.0.0/16 -> VNET B (Peered) (use mappings)
- 10.3.0.0/16 -> VNET C (Peered) (use mappings)
- 0/0 -> Default (Internet)
```



## Terminlogy

- **LPM**. LPM or longest prefix match refers to an algorithm used by routers in Internet Protocol (IP) networking to select an entry from a routing table.
Because each entry in a forwarding table may specify a sub-network, one destination address may match more than one forwarding table entry.
The most specific of the matching table entries — the one with the longest subnet mask — is called the longest prefix match.
It is called this because it is also the entry where the largest number of leading address bits of the destination address match those in the table entry.
- **Routing**. Routing is the process of sending a packet of information from one network to another network. Routers build **routing tables** that contain the following information:
  - Destination network and subnet mask.
  - Next hop to get to the destination network.
  - Routing metrics.