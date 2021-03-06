/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD 
// modified by yunhaj47
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  bool reqRmFlag = false;
  for (const auto& req_it : m_arpRequests) 
  {
    handle_arpreq(req_it, reqRmFlag);
    if(reqRmFlag) break;
  }

  std::vector<std::shared_ptr<ArpEntry>> arp_cache_tobe_removed;
  for (const auto& entry_it : m_cacheEntries) 
  { // entry is of type ArpEntry
    if (!(entry_it->isValid)) arp_cache_tobe_removed.push_back(entry_it);
  }

  for (const auto& entry_it : arp_cache_tobe_removed) 
  {
    m_cacheEntries.remove(entry_it);
  }

  // FILL THIS IN

}

void
ArpCache::send_queuing_packets(struct arp_hdr &reply_arp_hdr, uint32_t dst_ip)
{
  //find the corresponding request
  std::shared_ptr<ArpRequest> req = nullptr;
  for(const auto& req_it : m_arpRequests)
  {
      if(req_it->ip == dst_ip)
      {
          req = req_it;
          break;
      }
  }
  
  if(req != nullptr)
  {
    for(const auto& queuing_packet: req->packets)
    {
      int packet_size = queuing_packet.packet.size();
      Buffer temp_packet = std::vector<unsigned char>(packet_size, 0);
      struct ethernet_hdr eth_hdr;
      // swap the src and dest IP addr in the ETHERNET header
      memcpy(eth_hdr.ether_dhost, &reply_arp_hdr.arp_sha[0], ETHER_ADDR_LEN);
      memcpy(eth_hdr.ether_shost, &reply_arp_hdr.arp_tha[0], ETHER_ADDR_LEN);
      eth_hdr.ether_type = htons(0x0800);
      //Assemble packet
      memcpy(&temp_packet[0], &eth_hdr, sizeof(eth_hdr));
      memcpy(&temp_packet[14], &queuing_packet.packet[14], packet_size - sizeof(eth_hdr));
      std::string outgoing_iface_name = m_router.getRoutingTable().lookup(dst_ip).ifName;

      const Interface* sendInterface = m_router.findIfaceByName(outgoing_iface_name);
      m_router.sendPacket(temp_packet, sendInterface->name);
    }
    m_arpRequests.remove(req);

  }
}

void
ArpCache::handle_arpreq(std::shared_ptr<ArpRequest> req, bool &reqRmFlag) 
{
  if(steady_clock::now() - req->timeSent > seconds(1))
  {
    if(req->nTimesSent >= MAX_SENT_TIME)//reqeust time out(After 5 times retransmission)
    {
      printf("##############    Remove the request   ##############\n");
      m_arpRequests.remove(req);
      reqRmFlag = true;
      return;

    }
    else // again, send arp request
    {
      struct ethernet_hdr eth_hdr;
      struct arp_hdr arp_hdr;
      Buffer request_packet ((int)(sizeof(eth_hdr) + sizeof(arp_hdr)),0); //Sending packet 42 bytes

      //get the interface
      std::string outgoing_iface_name = m_router.getRoutingTable().lookup(req->ip).ifName;
      const Interface* outgoing_interface = m_router.findIfaceByName(outgoing_iface_name);   // outgoing interface mac address

      m_router.assembleArpRequestPacket(request_packet, outgoing_interface, req->ip);
      m_router.sendPacket(request_packet, outgoing_interface->name);

      printf("Sent Arp reqeust\n");
      std::cout << "outgoing Interface:" << outgoing_interface->name << std::endl; 
      req->timeSent = steady_clock::now();
      req->nTimesSent++;
    }
  }

}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry> // 用于查找该IP地址是否在 ARP table 中
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex); /////////////////////
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC                     IP              AGE         VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "       "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds "
       << "       " 
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
