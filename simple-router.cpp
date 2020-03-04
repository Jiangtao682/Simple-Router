/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  struct ethernet_hdr ethernet_header;
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;
  std::cerr << "test point 1" << std::endl;
  std::cerr << getArp() << std::endl;
  printIfaces(std::cout);
  dispachEthernetHeader(packet, ethernet_header); // get ethernet_header
  print_hdrs(packet);

  if(ethernet_header.ether_type == htons(ethertype_arp))
  {
    printf("Handle ARP request\n");
    handleArpPacket(packet, ethernet_header);
  }
  else if(ethernet_header.ether_type == htons(ethertype_ip))
  {
    printf("Handle IPv4 packet\n");
    handleIpPacket(packet, ethernet_header);
    printf("reveive a IPv4 header\n");
  }
}


void SimpleRouter::handleArpPacket(const Buffer &packet, struct ethernet_hdr &ether_hdr)
{
  struct arp_hdr arp_packet;
  getArpPacket(packet, arp_packet);

  if (arp_packet.arp_op==htons(arp_op_request)) // get an arp request massage
  {
    std::shared_ptr<ArpEntry> lookup_arp;
    lookup_arp = m_arp.lookup(arp_packet.arp_sip);
    if(lookup_arp == NULL)
    {
      Buffer source_mac_addr = std::vector<unsigned char>(ETHER_ADDR_LEN, 0); //6 char, val is 0
      memcpy(&source_mac_addr[0], &packet[6], ETHER_ADDR_LEN);
      m_arp.insertArpEntry(source_mac_addr, arp_packet.arp_sip);
    }
    const Interface *myInterface = findIfaceByIp(arp_packet.arp_tip);
    if (myInterface != nullptr)
    {
      Buffer reply_arp_packet;
      assembleArpInterfaceReplyPacket(reply_arp_packet, ether_hdr, arp_packet);
      sendPacket(reply_arp_packet, myInterface->name);
      printf("###########  send arp reply  ##############\n");
      print_hdrs(reply_arp_packet);
    }
  }
  else if(arp_packet.arp_op == htons(arp_op_reply)) // get an arp reply massage
  {
    std::shared_ptr<simple_router::ArpEntry> lookup = NULL;
    lookup = m_arp.lookup(arp_packet.arp_sip);//check ARP cache, if already there, discard else record mapping  
    if (lookup == NULL){ //not found the mapping in cache 
      Buffer source_mac_addr = std::vector<unsigned char>(6, 0);
      memcpy(&source_mac_addr[0], &packet[6], ETHER_ADDR_LEN);
      m_arp.insertArpEntry(source_mac_addr,arp_packet.arp_sip);
      
      //It will remove the request after sending all packets
      m_arp.sendPendingPackets(arp_packet, arp_packet.arp_sip);
    }
    else 
        printf("ARP reply's mapping already in cache, ARP packet drop\n");
  }

}

void SimpleRouter::handleIpPacket(const Buffer &packet, struct ethernet_hdr &ether_hdr)
{
  struct ip_hdr ip_packet;
  const Interface *myInterface;
  Buffer ip_packet_to_sent = packet;
  getIpPacket(packet, ip_packet);  //should be get ip header
  uint8_t TTL = ip_packet.ip_ttl - 1;

  if(m_arp.lookup(ip_packet.ip_src) == nullptr)
    {
      printf("##############    source not in ARP chache\n");
      Buffer source_mac = std::vector<unsigned char>(6, 0);
      memcpy(&source_mac[0], &packet[6], ETHER_ADDR_LEN);
      m_arp.insertArpEntry(source_mac ,ip_packet.ip_src);
    }
    else
    {
      printf("##################  source is in ARP \n");
    }

  printf("################  checksum is %x\n", cksum(&ip_packet, sizeof(ip_packet)));
  if(cksum(&ip_packet, sizeof(ip_packet)) == 0xffff) //checksum is correct
  {
    ip_packet.ip_ttl = TTL;
    myInterface = findIfaceByIp(ip_packet.ip_dst);
    if (myInterface == nullptr) // this packet is not dested to the router i.e datagram to be forwarded
    {
      if (TTL <= 0)  // send ICMP packet for ttl time exceeded 
      {
        if(m_arp.lookup(ip_packet.ip_src) == nullptr)  // update arp table
        {
          Buffer source_mac = std::vector<unsigned char>(6, 0);
          memcpy(&source_mac[0], &packet[6], ETHER_ADDR_LEN);
          m_arp.insertArpEntry(source_mac ,ip_packet.ip_src);
        }
        handleIcmpPacket(packet, ether_hdr, 1);
      }
      else if(m_arp.lookup(ip_packet.ip_dst) != nullptr) // find dest ip in arp cache
      {
        try{ 
          ip_packet.ip_ttl = TTL;
          RoutingTableEntry matched_entry = m_routingTable.lookup(ip_packet.ip_dst);
          ip_packet.ip_sum = 0x0000; //zero the checksum and then calculate
          ip_packet.ip_sum = cksum(&ip_packet,sizeof(ip_packet)); //update IP checksum                     
          printf("in forwarding ttl is %x\n", ip_packet.ip_ttl);
          std::shared_ptr<simple_router::ArpEntry> dest_mac;
          if (ipToString(matched_entry.dest).compare("0.0.0.0") == 0)
             dest_mac = m_arp.lookup(ip_packet.ip_dst);  
          else
             dest_mac = m_arp.lookup(matched_entry.dest);
          
          const Interface *interToForward = findIfaceByName(matched_entry.ifName);
          memcpy(ether_hdr.ether_shost, &interToForward->addr[0], sizeof(ether_hdr.ether_shost)); //change source mac address to be iface mac
          memcpy(ether_hdr.ether_dhost, (dest_mac->mac).data(), sizeof(ether_hdr.ether_dhost)); //change dest mac address

          assembleIPPacket(ip_packet_to_sent, ip_packet, ether_hdr); //update IP header, including MAC address
          sendPacket(ip_packet_to_sent, matched_entry.ifName); //forward packet
          print_hdrs(ip_packet_to_sent);
        }
        catch (std::runtime_error& error){ //if not found in forwarding table
          printf("Packet discard because of no match in forwarding table\n");
        }
        printf("==============packet sent out================\n");
      }
      else //if no arp found in cache, packet must be pushed to queue
      {
        Buffer dummy = std::vector<unsigned char>(6,0);
        std::memcpy(&dummy[0],&ether_hdr.ether_dhost,sizeof(ether_hdr.ether_dhost));
        const Buffer dummy_2 = dummy;
        const Interface *myInter = findIfaceByMac(dummy_2);   
        m_arp.queueRequest(ip_packet.ip_dst, packet, myInter->name); 
        printf("Finish this function\n");
      }
    }
    else // could be a ICMP packet
    {
      if(ip_packet.ip_p == ip_protocol_icmp) // ICMP 
        handleIcmpPacket(packet, ether_hdr, 0);
      else if(ip_packet.ip_p == 0x11)// protocol is 17 means the traceroute 
        handleIcmpPacket(packet, ether_hdr, 0);  // send a port unreachable ICMP massage
    }
  }
  else
  {
    printf("Checksum is wrong\n");
  }

}


void 
SimpleRouter::handleIcmpPacket(const Buffer &packet, struct ethernet_hdr &e_hdr, int time_exceed)
{
struct icmp_hdr icmp_packet;  // packet should be changed with header
getIcmpPacket(packet, icmp_packet);
if(icmp_packet.icmp_type == 8)//ICMP echo message, we need to send an echo reply message
{
  printf("received a ICMP echo message\n");
  uint16_t padd_cksum = 0x0000;
  Buffer temp_packet = packet;
  memcpy(&temp_packet[36], &padd_cksum, sizeof(padd_cksum));
  if(cksum(&temp_packet[34], (int)sizeof(temp_packet) - 34) == 0xffff)//valid ICMP packet
  {
    //ICMP Layer
    //change ICMP type
    //change checksum include data
    uint8_t icmp_type;
    if(time_exceed == 0) //time not exceeded
      icmp_type = 0x00;
    else
      icmp_type = 0x0b; //set type with 11
    memcpy(&temp_packet[34], &icmp_type, sizeof(icmp_type));
    uint16_t icmp_sum = cksum(&temp_packet[34], (int)sizeof(temp_packet) - 34);
    memcpy(&temp_packet[36], &icmp_sum, sizeof(icmp_packet.icmp_sum));

    //IP layer
    //change dest ip
    //change source ip
    //change ip checksum ip header only
    // uint32_t temp_src_ip = myInterface->ip;
    struct ip_hdr temp_ip_hdr;
    uint8_t padd_ip_cksum = 0x00;
    memcpy(&temp_packet[24], &padd_ip_cksum, sizeof(padd_ip_cksum));
    getIpPacket(temp_packet, temp_ip_hdr);
    memcpy(&temp_packet[30], &temp_ip_hdr.ip_src, sizeof(uint32_t));
    memcpy(&temp_packet[26], &temp_ip_hdr.ip_dst, sizeof(uint32_t));
    uint8_t ip_sum = cksum(&temp_packet[14], sizeof(struct ip_hdr));
    memcpy(&temp_packet[24], &ip_sum, sizeof(ip_sum));
    

    //Ethernet layer
    //change destination address
    //change source address
    // const Interface* myInterface = findIfaceByIp(temp_src_ip);  
    // const Interface* myInterface = findIfaceByName(temp_iface);
    Buffer my_mac_addr = std::vector<unsigned char>(6, 0);
    memcpy(&my_mac_addr[0], &e_hdr.ether_dhost[0], ETHER_ADDR_LEN);
    const Interface* myInterface = findIfaceByMac(my_mac_addr);
    memcpy(&temp_packet[0], &temp_packet[6], sizeof(e_hdr.ether_shost));
    memcpy(&temp_packet[6], &e_hdr.ether_dhost[0], sizeof(e_hdr.ether_shost));

    sendPacket(temp_packet, myInterface->name);
    printf("#############  send ICMP echo reply  ############# \n");
    print_hdrs(temp_packet);
  }

}
else  // Do not have ICMP message, time exceeded or dest port unreachable
{
  
  // uint8_t ip_protocol; ip protocol type should be changed
  // memcpy(&ip_protocol, &packet[23], sizeof(uint8_t));
  Buffer temp_packet;
  temp_packet = std::vector<unsigned char>(70, 0);

  //ICMP Layer
  //change ICMP type and code
  //change checksum include data
  //add IP header and 8 byte original datagram
  uint8_t icmp_type;
  uint8_t icmp_code;
  if(time_exceed == 0) //time not exceeded
  {
    icmp_type = 0x03;
    icmp_code = 0x03;
  }
  else
  {
    icmp_type = 0x0b; //type = 11
    icmp_code = 0x00;
  }  
  memcpy(&temp_packet[42], &packet[14], 28);  //prepare datagram
  memcpy(&temp_packet[34], &icmp_type, sizeof(icmp_type));
  memcpy(&temp_packet[35], &icmp_code, sizeof(icmp_code));
  uint16_t padd_cksum = 0x0000;
  memcpy(&temp_packet[36], &padd_cksum, sizeof(padd_cksum));
  uint16_t icmp_sum = cksum(&temp_packet[34], 36);
  memcpy(&temp_packet[36], &icmp_sum, 2);

  //IP layer
  //change dest ip
  //change source ip
  //change protocol type
  //change ip checksum ip header only
  struct ip_hdr temp_ip_hdr;
  getIpPacket(packet, temp_ip_hdr);

  Buffer my_mac_addr = std::vector<unsigned char>(6, 0);
  memcpy(&my_mac_addr[0], &e_hdr.ether_dhost[0], ETHER_ADDR_LEN);
  const Interface* myInterface = findIfaceByMac(my_mac_addr); 
  uint32_t temp_src_ip;
  temp_src_ip = temp_ip_hdr.ip_src;

  const Interface* router_Interface = findIfaceByIp(temp_ip_hdr.ip_dst);
  if(router_Interface == nullptr)
  {
    temp_ip_hdr.ip_src = myInterface->ip;
  }
  else
  {
    temp_ip_hdr.ip_src = temp_ip_hdr.ip_dst;
  }
  temp_ip_hdr.ip_dst = temp_src_ip;
  temp_ip_hdr.ip_p = ip_protocol_icmp;
  temp_ip_hdr.ip_ttl = 0x40;
  temp_ip_hdr.ip_sum = 0x00;
  temp_ip_hdr.ip_len = htons(0x38);
  memcpy(&temp_packet[14], &temp_ip_hdr, sizeof(temp_ip_hdr));
  uint16_t ip_sum = cksum(&temp_packet[14], sizeof(temp_ip_hdr));
  memcpy(&temp_packet[24], &ip_sum, sizeof(ip_sum));

  //Ethernet layer
  //change destination address
  //change source address
  memcpy(&temp_packet[0], &packet[0], 14);
  memcpy(&temp_packet[0], &packet[6], sizeof(e_hdr.ether_shost));
  memcpy(&temp_packet[6], &myInterface->addr[0], sizeof(e_hdr.ether_shost));

  sendPacket(temp_packet, myInterface->name);
  printf("#############   send ICMP Timeout or unreachable packet  ###########\n");
  print_hdrs(temp_packet);
}

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
