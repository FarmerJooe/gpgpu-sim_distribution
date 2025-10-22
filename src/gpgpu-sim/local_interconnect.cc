// Copyright (c) 2019, Mahmoud Khairy
// Purdue University
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. Neither the name of
// The University of British Columbia nor the names of its contributors may be
// used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

#include "local_interconnect.h"
#include "mem_fetch.h"

static void print_router_extended_stats(const xbar_router *router,
                                        const char *prefix) {
  if (!router) return;

  unsigned total_inputs = router->in_buffer_full_events_by_input.size();
  unsigned total_outputs = router->blocked_by_output_busy_by_output.size();

  for (unsigned in = 0; in < router->conflict_matrix.size(); ++in) {
    for (unsigned out = 0; out < router->conflict_matrix[in].size(); ++out) {
      unsigned long long value = router->conflict_matrix[in][out];
      if (value)
        printf("%s_conflict_matrix[%u->%u] = %llu\n", prefix, in, out, value);
    }
  }

  for (unsigned out = 0; out < total_outputs; ++out) {
    unsigned long long busy = router->blocked_by_output_busy_by_output[out];
    unsigned long long full = router->blocked_by_full_buffer_by_output[out];
    unsigned long long full_events = router->out_buffer_full_events_by_output[out];
    if (busy || full || full_events)
      printf("%s_output[%u]_busy_conflicts = %llu blocked_by_full = %llu full_events = %llu\n",
             prefix, out, busy, full, full_events);
  }

  for (unsigned in = 0; in < total_inputs; ++in) {
    unsigned long long busy = router->blocked_by_output_busy_by_input[in];
    unsigned long long full = router->blocked_by_full_buffer_by_input[in];
    unsigned long long events = router->in_buffer_full_events_by_input[in];
    if (busy || full || events) {
      unsigned long long avg_wait =
          events ? router->in_buffer_full_wait_sum_by_input[in] / events : 0;
      printf(
          "%s_input[%u]_busy_conflicts = %llu blocked_by_full = %llu in_buf_full = %llu avg_wait = %llu max_wait = %llu\n",
          prefix, in, busy, full, events, avg_wait,
          router->in_buffer_full_wait_max_by_input[in]);
    }
  }
}

xbar_router::xbar_router(unsigned router_id, enum Interconnect_type m_type,
                         unsigned n_shader, unsigned n_mem,
                         const struct inct_config& m_localinct_config) {
  m_id = router_id;
  router_type = m_type;
  _n_mem = n_mem;
  _n_shader = n_shader;
  total_nodes = n_shader + n_mem;
  verbose = m_localinct_config.verbose;
  grant_cycles = m_localinct_config.grant_cycles;
  grant_cycles_count = m_localinct_config.grant_cycles;
  in_buffers.resize(total_nodes);
  out_buffers.resize(total_nodes);
  next_node.resize(total_nodes, 0);
  in_buffer_limit = m_localinct_config.in_buffer_limit;
  out_buffer_limit = m_localinct_config.out_buffer_limit;
  arbit_type = m_localinct_config.arbiter_algo;
  next_node_id = 0;
  if (m_type == REQ_NET) {
    active_in_buffers = n_shader;
    active_out_buffers = n_mem;
  } else if (m_type == REPLY_NET) {
    active_in_buffers = n_mem;
    active_out_buffers = n_shader;
  }

  cycles = 0;
  conflicts = 0;
  out_buffer_full = 0;
  in_buffer_full = 0;
  out_buffer_util = 0;
  in_buffer_util = 0;
  packets_num = 0;
  conflicts_util = 0;
  cycles_util = 0;
  reqs_util = 0;

  conflict_matrix.assign(total_nodes,
                         std::vector<unsigned long long>(total_nodes, 0));
  blocked_by_output_busy_by_output.assign(total_nodes, 0);
  blocked_by_output_busy_by_input.assign(total_nodes, 0);
  blocked_by_full_buffer_by_output.assign(total_nodes, 0);
  blocked_by_full_buffer_by_input.assign(total_nodes, 0);
  out_buffer_full_events_by_output.assign(total_nodes, 0);
  in_buffer_full_events_by_input.assign(total_nodes, 0);
  in_buffer_full_wait_sum_by_input.assign(total_nodes, 0);
  in_buffer_full_wait_max_by_input.assign(total_nodes, 0);
}

xbar_router::~xbar_router() {}

void xbar_router::Push(unsigned input_deviceID, unsigned output_deviceID,
                       void* data, unsigned int size) {
  assert(input_deviceID < total_nodes);
  in_buffers[input_deviceID].push(
      Packet(data, output_deviceID, cycles, input_deviceID));
  packets_num++;
}

void* xbar_router::Pop(unsigned ouput_deviceID) {
  assert(ouput_deviceID < total_nodes);
  void* data = NULL;

  if (!out_buffers[ouput_deviceID].empty()) {
    data = out_buffers[ouput_deviceID].front().data;
    out_buffers[ouput_deviceID].pop();
  }

  return data;
}

bool xbar_router::Has_Buffer_In(unsigned input_deviceID, unsigned size,
                                bool update_counter) {
  assert(input_deviceID < total_nodes);

  bool has_buffer =
      (in_buffers[input_deviceID].size() + size <= in_buffer_limit);
  if (update_counter && !has_buffer) {
    in_buffer_full++;
    in_buffer_full_events_by_input[input_deviceID]++;
    if (!in_buffers[input_deviceID].empty()) {
      unsigned long long wait_cycles =
          cycles - in_buffers[input_deviceID].front().enqueue_cycle;
      in_buffer_full_wait_sum_by_input[input_deviceID] += wait_cycles;
      if (wait_cycles > in_buffer_full_wait_max_by_input[input_deviceID])
        in_buffer_full_wait_max_by_input[input_deviceID] = wait_cycles;
    }
  }

  return has_buffer;
}

bool xbar_router::Has_Buffer_Out(unsigned output_deviceID, unsigned size) {
  return (out_buffers[output_deviceID].size() + size <= out_buffer_limit);
}

void xbar_router::Advance() {
  if (arbit_type == NAIVE_RR)
    RR_Advance();
  else if (arbit_type == iSLIP)
    iSLIP_Advance();
  else
    assert(0);
}

void xbar_router::RR_Advance() {
  bool active = false;
  vector<bool> issued(total_nodes, false);
  unsigned conflict_sub = 0;
  unsigned reqs = 0;

  for (unsigned i = 0; i < total_nodes; ++i) {
    unsigned node_id = (i + next_node_id) % total_nodes;

    if (!in_buffers[node_id].empty()) {
      active = true;
      Packet _packet = in_buffers[node_id].front();
      // ensure that the outbuffer has space and not issued before in this cycle
      if (Has_Buffer_Out(_packet.output_deviceID, 1)) {
        if (!issued[_packet.output_deviceID]) {
          out_buffers[_packet.output_deviceID].push(_packet);
          in_buffers[node_id].pop();
          issued[_packet.output_deviceID] = true;
          reqs++;
        } else
          {
            conflict_sub++;
            conflict_matrix[node_id][_packet.output_deviceID]++;
            blocked_by_output_busy_by_output[_packet.output_deviceID]++;
            blocked_by_output_busy_by_input[node_id]++;
          }
      } else {
        out_buffer_full++;
        out_buffer_full_events_by_output[_packet.output_deviceID]++;
        blocked_by_full_buffer_by_output[_packet.output_deviceID]++;
        blocked_by_full_buffer_by_input[node_id]++;

        if (issued[_packet.output_deviceID]) {
          conflict_sub++;
          conflict_matrix[node_id][_packet.output_deviceID]++;
        }
      }
    }
  }

  next_node_id = (++next_node_id % total_nodes);

  conflicts += conflict_sub;
  if (active) {
    conflicts_util += conflict_sub;
    cycles_util++;
    reqs_util += reqs;
  }

  if (verbose) {
    printf("%d : cycle %d : conflicts = %d\n", m_id, cycles, conflict_sub);
    printf("%d : cycle %d : passing reqs = %d\n", m_id, cycles, reqs);
  }

  // collect some stats about buffer util
  for (unsigned i = 0; i < total_nodes; ++i) {
    in_buffer_util += in_buffers[i].size();
    out_buffer_util += out_buffers[i].size();
  }

  cycles++;
}

// iSLIP algorithm
// McKeown, Nick. "The iSLIP scheduling algorithm for input-queued switches."
// IEEE/ACM transactions on networking 2 (1999): 188-201.
// https://www.cs.rutgers.edu/~sn624/552-F18/papers/islip.pdf
void xbar_router::iSLIP_Advance() {
  std::vector<int> first_requester(total_nodes, -1);
  bool active = false;

  unsigned conflict_sub = 0;
  unsigned reqs = 0;

  // calculate how many conflicts are there for stats
  for (unsigned i = 0; i < total_nodes; ++i) {
    if (!in_buffers[i].empty()) {
      Packet _packet_tmp = in_buffers[i].front();
      unsigned out = _packet_tmp.output_deviceID;
      if (first_requester[out] == -1) {
        first_requester[out] = static_cast<int>(i);
      } else {
        conflict_sub++;
        conflict_matrix[i][out]++;
        blocked_by_output_busy_by_output[out]++;
        blocked_by_output_busy_by_input[i]++;
      }
      active = true;
    }
  }

  conflicts += conflict_sub;
  if (active) {
    conflicts_util += conflict_sub;
    cycles_util++;
  }
  // do iSLIP
  for (unsigned i = 0; i < total_nodes; ++i) {
    if (Has_Buffer_Out(i, 1)) {
      for (unsigned j = 0; j < total_nodes; ++j) {
        unsigned node_id = (j + next_node[i]) % total_nodes;

        if (!in_buffers[node_id].empty()) {
          Packet _packet = in_buffers[node_id].front();
          if (_packet.output_deviceID == i) {
            out_buffers[_packet.output_deviceID].push(_packet);
            in_buffers[node_id].pop();
            if (verbose)
              printf("%d : cycle %d : send req from %d to %d\n", m_id, cycles,
                     node_id, i - _n_shader);
            if (grant_cycles_count == 1)
              next_node[i] = (++node_id % total_nodes);
            if (verbose) {
              for (unsigned k = j + 1; k < total_nodes; ++k) {
                unsigned node_id2 = (k + next_node[i]) % total_nodes;
                if (!in_buffers[node_id2].empty()) {
                  Packet _packet2 = in_buffers[node_id2].front();

                  if (_packet2.output_deviceID == i)
                    printf("%d : cycle %d : cannot send req from %d to %d\n",
                           m_id, cycles, node_id2, i - _n_shader);
                }
              }
            }

            reqs++;
            break;
          }
        }
      }
    } else {
      out_buffer_full++;
      out_buffer_full_events_by_output[i]++;
      int blocking_input = first_requester[i];
      if (blocking_input >= 0) {
        blocked_by_full_buffer_by_output[i]++;
        blocked_by_full_buffer_by_input[blocking_input]++;
      }
    }
  }

  if (active) {
    reqs_util += reqs;
  }

  if (verbose)
    printf("%d : cycle %d : grant_cycles = %d\n", m_id, cycles, grant_cycles);

  if (active && grant_cycles_count == 1)
    grant_cycles_count = grant_cycles;
  else if (active)
    grant_cycles_count--;

  if (verbose) {
    printf("%d : cycle %d : conflicts = %d\n", m_id, cycles, conflict_sub);
    printf("%d : cycle %d : passing reqs = %d\n", m_id, cycles, reqs);
  }

  // collect some stats about buffer util
  for (unsigned i = 0; i < total_nodes; ++i) {
    in_buffer_util += in_buffers[i].size();
    out_buffer_util += out_buffers[i].size();
  }

  cycles++;
}

bool xbar_router::Busy() const {
  for (unsigned i = 0; i < total_nodes; ++i) {
    if (!in_buffers[i].empty()) return true;

    if (!out_buffers[i].empty()) return true;
  }
  return false;
}

////////////////////////////////////////////////////
/////////////LocalInterconnect/////////////////////

// assume all the packets are one flit
#define LOCAL_INCT_FLIT_SIZE 40

LocalInterconnect* LocalInterconnect::New(
    const struct inct_config& m_localinct_config) {
  LocalInterconnect* icnt_interface = new LocalInterconnect(m_localinct_config);

  return icnt_interface;
}

LocalInterconnect::LocalInterconnect(
    const struct inct_config& m_localinct_config)
    : m_inct_config(m_localinct_config) {
  n_shader = 0;
  n_mem = 0;
  n_subnets = m_localinct_config.subnets;
}

LocalInterconnect::~LocalInterconnect() {
  for (unsigned i = 0; i < m_inct_config.subnets; ++i) {
    delete net[i];
  }
}

void LocalInterconnect::CreateInterconnect(unsigned m_n_shader,
                                           unsigned m_n_mem) {
  n_shader = m_n_shader;
  n_mem = m_n_mem;

  net.resize(n_subnets);
  for (unsigned i = 0; i < n_subnets; ++i) {
    net[i] = new xbar_router(i, static_cast<Interconnect_type>(i), m_n_shader,
                             m_n_mem, m_inct_config);
  }
}

void LocalInterconnect::Init() {
  // empty
  // there is nothing to do
}

void LocalInterconnect::Push(unsigned input_deviceID, unsigned output_deviceID,
                             void* data, unsigned int size) {
  unsigned subnet;
  if (n_subnets == 1) {
    subnet = 0;
  } else {
    if (input_deviceID < n_shader) {
      subnet = 0;
    } else {
      subnet = 1;
    }
  }

  // it should have free buffer
  // assume all the packets have size of one
  // no flits are implemented
  assert(net[subnet]->Has_Buffer_In(input_deviceID, 1));

  net[subnet]->Push(input_deviceID, output_deviceID, data, size);
}

void* LocalInterconnect::Pop(unsigned ouput_deviceID) {
  // 0-_n_shader-1 indicates reply(network 1), otherwise request(network 0)
  int subnet = 0;
  if (ouput_deviceID < n_shader) subnet = 1;

  return net[subnet]->Pop(ouput_deviceID);
}

void LocalInterconnect::Advance() {
  for (unsigned i = 0; i < n_subnets; ++i) {
    net[i]->Advance();
  }
}

bool LocalInterconnect::Busy() const {
  for (unsigned i = 0; i < n_subnets; ++i) {
    if (net[i]->Busy()) return true;
  }
  return false;
}

bool LocalInterconnect::HasBuffer(unsigned deviceID, unsigned int size) const {
  bool has_buffer = false;

  if ((n_subnets > 1) && deviceID >= n_shader)  // deviceID is memory node
    has_buffer = net[REPLY_NET]->Has_Buffer_In(deviceID, 1, true);
  else
    has_buffer = net[REQ_NET]->Has_Buffer_In(deviceID, 1, true);

  return has_buffer;
}

void LocalInterconnect::DisplayStats() const {
  printf("Req_Network_injected_packets_num = %lld\n",
         net[REQ_NET]->packets_num);
  printf("Req_Network_cycles = %lld\n", net[REQ_NET]->cycles);
  printf("Req_Network_injected_packets_per_cycle = %12.4f \n",
         (float)(net[REQ_NET]->packets_num) / (net[REQ_NET]->cycles));
  printf("Req_Network_conflicts_per_cycle = %12.4f\n",
         (float)(net[REQ_NET]->conflicts) / (net[REQ_NET]->cycles));
  printf("Req_Network_conflicts_per_cycle_util = %12.4f\n",
         (float)(net[REQ_NET]->conflicts_util) / (net[REQ_NET]->cycles_util));
  printf("Req_Bank_Level_Parallism = %12.4f\n",
         (float)(net[REQ_NET]->reqs_util) / (net[REQ_NET]->cycles_util));
  printf("Req_Network_in_buffer_full_per_cycle = %12.4f\n",
         (float)(net[REQ_NET]->in_buffer_full) / (net[REQ_NET]->cycles));
  printf("Req_Network_in_buffer_avg_util = %12.4f\n",
         ((float)(net[REQ_NET]->in_buffer_util) / (net[REQ_NET]->cycles) /
          net[REQ_NET]->active_in_buffers));
  printf("Req_Network_out_buffer_full_per_cycle = %12.4f\n",
         (float)(net[REQ_NET]->out_buffer_full) / (net[REQ_NET]->cycles));
  printf("Req_Network_out_buffer_avg_util = %12.4f\n",
         ((float)(net[REQ_NET]->out_buffer_util) / (net[REQ_NET]->cycles) /
          net[REQ_NET]->active_out_buffers));

  print_router_extended_stats(net[REQ_NET], "Req");

  printf("\n");
  printf("Reply_Network_injected_packets_num = %lld\n",
         net[REPLY_NET]->packets_num);
  printf("Reply_Network_cycles = %lld\n", net[REPLY_NET]->cycles);
  printf("Reply_Network_injected_packets_per_cycle =  %12.4f\n",
         (float)(net[REPLY_NET]->packets_num) / (net[REPLY_NET]->cycles));
  printf("Reply_Network_conflicts_per_cycle =  %12.4f\n",
         (float)(net[REPLY_NET]->conflicts) / (net[REPLY_NET]->cycles));
  printf(
      "Reply_Network_conflicts_per_cycle_util = %12.4f\n",
      (float)(net[REPLY_NET]->conflicts_util) / (net[REPLY_NET]->cycles_util));
  printf("Reply_Bank_Level_Parallism = %12.4f\n",
         (float)(net[REPLY_NET]->reqs_util) / (net[REPLY_NET]->cycles_util));
  printf("Reply_Network_in_buffer_full_per_cycle = %12.4f\n",
         (float)(net[REPLY_NET]->in_buffer_full) / (net[REPLY_NET]->cycles));
  printf("Reply_Network_in_buffer_avg_util = %12.4f\n",
         ((float)(net[REPLY_NET]->in_buffer_util) / (net[REPLY_NET]->cycles) /
          net[REPLY_NET]->active_in_buffers));
  printf("Reply_Network_out_buffer_full_per_cycle = %12.4f\n",
         (float)(net[REPLY_NET]->out_buffer_full) / (net[REPLY_NET]->cycles));
  printf("Reply_Network_out_buffer_avg_util = %12.4f\n",
         ((float)(net[REPLY_NET]->out_buffer_util) / (net[REPLY_NET]->cycles) /
          net[REPLY_NET]->active_out_buffers));

  print_router_extended_stats(net[REPLY_NET], "Reply");
}

void LocalInterconnect::DisplayOverallStats() const {}

unsigned LocalInterconnect::GetFlitSize() const { return LOCAL_INCT_FLIT_SIZE; }

void LocalInterconnect::DisplayState(FILE* fp) const {
  fprintf(fp, "GPGPU-Sim uArch: ICNT:Display State: Under implementation\n");
}
