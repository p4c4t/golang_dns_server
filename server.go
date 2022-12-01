package main

import (
	"fmt"
	"net"
)

type query struct {
	name        []byte
	query_type  uint16
	query_class uint16
}

type dns_request struct {
	transaction_id uint16
	flags          uint16
	queries_n      uint16
	responses_n    uint16
	authority_n    uint16
	additional_n   uint16
	queries        []query
}

type response struct {
	name           uint16
	response_type  uint16
	response_class uint16
	ttl            uint32
	data_length    uint16
	data           []byte
}

type dns_response struct {
	transaction_id uint16
	flags          uint16
	queries_n      uint16
	responses_n    uint16
	authority_n    uint16
	additional_n   uint16
	queries        []query
	responses      []response
}

func is_allowed(c byte) bool {
	return (c <= 122 && c >= 97) || (c <= 90 && c >= 65) || c == 45 || c == 3
}

func main() {
	serverPort := 3044
	addr := net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP("0.0.0.0"),
	}
	server, err := net.ListenUDP("udp", &addr)
	server.SetReadBuffer(1024)
	if err != nil {
		return
	}
	for {
		read := make([]byte, 1024)
		var pck dns_request
		num_read, addr, err := server.ReadFromUDP(read)
		if err != nil {
			return
		}
		fmt.Println(read[:num_read])
		pck.transaction_id = uint16(read[0])<<8 + uint16(read[1])
		pck.flags = uint16(read[2])<<8 + uint16(read[3])
		pck.queries_n = uint16(read[4])<<8 + uint16(read[5])
		pck.queries = make([]query, pck.queries_n)
		pck.responses_n = 0  // uint16(read[6])<<8 + uint16(read[7])
		pck.authority_n = 0  // uint16(read[8])<<8 + uint16(read[9])
		pck.additional_n = 0 // uint16(read[10])<<8 + uint16(read[11])
		j := uint(12)
		if pck.queries_n != 1 {
			panic("multiple queries in one packet not implemented")
		}
		for i := uint16(0); i < pck.queries_n; i++ {
			ti := j
			for read[ti] != 0 && ti < uint(num_read) {
				ti++
			}
			if ti == uint(num_read) {
				panic("invalid packet: reached end of packet before end of string")
			}
			pck.queries[i] = query{
				name:        read[j:ti],
				query_type:  uint16(read[ti+1])<<8 + uint16(read[ti+2]),
				query_class: uint16(read[ti+3])<<8 + uint16(read[ti+4]),
			}
		}
		handle_request(server, addr, &pck)
	}
}

func dns_to_str(host []byte) string {
	host_dot := make([]byte, len(host))
	copy(host_dot, host)
	i, _ := 0, 0
	for {
		i = i + int(host_dot[i]) + 1
		if i > len(host) {
			break
		}
		host_dot[i] = 46 // dot
	}
	return string(host_dot[1:])
}

func handle_request(server *net.UDPConn, client *net.UDPAddr, req *dns_request) {
	if req.queries_n != 1 {
		panic("multiple queries in one packet not yet implemented")
	}
	resp := dns_response{
		transaction_id: req.transaction_id,
		responses_n:    req.queries_n,
		responses:      make([]response, 0),
		queries_n:      req.queries_n,
		queries:        req.queries,
		authority_n:    0,
		additional_n:   0,
		flags:          0b1000_0001_1000_0000,
	}
	for _, query := range resp.queries {
		ips, err := net.LookupIP(dns_to_str(query.name))
		if err != nil {
			panic("wasn't able to look up dns")
		}
		for _, ip := range ips {
			if ip.To4() == nil {
				continue
			}
			resp.responses = append(resp.responses, response{
				name:           0xc00c,
				response_type:  0x0001,
				response_class: 0x0001,
				ttl:            0xffff,
				data_length:    4,
				data:           ip.To4(),
			})
			break
		}
	}
	buff := make([]byte, 0)
	buff = append(
		buff,
		byte(resp.transaction_id>>8),
		byte(resp.transaction_id),
		byte(resp.flags>>8),
		byte(resp.flags),
		byte(resp.queries_n>>8),
		byte(resp.queries_n),
		byte(resp.responses_n>>8),
		byte(resp.responses_n),
		byte(resp.authority_n>>8),
		byte(resp.authority_n),
		byte(resp.additional_n>>8),
		byte(resp.additional_n),
	)
	for _, query := range resp.queries {
		buff = append(
			buff,
			query.name...,
		)
		buff = append(
			buff,
			0x00,
			byte(query.query_type>>8),
			byte(query.query_type),
			byte(query.query_class>>8),
			byte(query.query_class),
		)
	}
	for _, response := range resp.responses {
		buff = append(
			buff,
			byte(response.name>>8),
			byte(response.name),
			byte(response.response_type>>8),
			byte(response.response_type),
			byte(response.response_class>>8),
			byte(response.response_class),
			byte(response.ttl>>24),
			byte(response.ttl>>16),
			byte(response.ttl>>8),
			byte(response.ttl),
			byte(response.data_length>>8),
			byte(response.data_length),
		)
		buff = append(buff,
			response.data...,
		)
	}
	fmt.Print(buff)
	server.WriteTo(buff, client)
}
