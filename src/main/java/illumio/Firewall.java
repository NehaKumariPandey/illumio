package illumio;

import com.google.common.net.InetAddresses;
import lombok.Data;
import org.apache.commons.lang3.Validate;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public class Firewall {

    private static final String CSV_DELIMITER = ",";
    private static final String RANGE_DELIMITER = "-";
    private static final String DOT_DELIMITER = "\\.";
    private static final String INBOUND = "inbound";
    private static final String OUTBOUND = "outbound";
    private static final String TCP = "tcp";

    private String path;
    private AddressNode inTcpTrie;
    private AddressNode inUdpTrie;
    private AddressNode outTcpTrie;
    private AddressNode outUdpTrie;

    /**
     * Constructor, taking a single string argument, which is a file path to a CSV file
     * Assumes that all content in the input file is valid.
     */
    public Firewall(final String path) throws IOException {
        this.path = Validate.notEmpty(path, "csv path is required!");
        this.inTcpTrie = new AddressNode(200, false);
        this.inUdpTrie = new AddressNode(200, false);
        this.outTcpTrie = new AddressNode(200, false);
        this.outUdpTrie = new AddressNode(200, false);
        parseCsvFile(path);
    }

    private void parseCsvFile(final String path) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(path), Charset.defaultCharset()));
        String line;
        while ((line  = br.readLine()) != null) {
            parseInputRecord(line.split(CSV_DELIMITER));
        }
        br.close();
    }

    /**
     * Add record to corresponding trie.
     * Assumes inputs are valid
     */
    private void parseInputRecord(final String[] recordArr) {
        final String direction = recordArr[0];
        final String protocol = recordArr[1];
        final String port = recordArr[2];
        final String ipAddress = recordArr[3];
        switch (direction) {
            case INBOUND:
                if (TCP.equals(protocol)) {
                    extractAllIPsAndPorts(inTcpTrie, ipAddress, port);
                } else {
                    extractAllIPsAndPorts(inUdpTrie, ipAddress, port);
                }
                break;
            case OUTBOUND:
                if (TCP.equals(protocol)) {
                    extractAllIPsAndPorts(outTcpTrie, ipAddress, port);
                } else {
                    extractAllIPsAndPorts(outUdpTrie, ipAddress, port);
                }
                break;
            default:
                throw new RuntimeException("Internal server error!");
        }
    }

    /**
     * Put a single ip address or add a list of ips to the trie.
     */
    private void extractAllIPsAndPorts(final AddressNode trie, final String ipString, final String port) {
        if (!ipString.contains(RANGE_DELIMITER)) {
            addToTrie(trie, ipString, port);
        } else {
            String[] ipRangeArr = ipString.split(RANGE_DELIMITER);
            int lowIpInt = InetAddresses.coerceToInteger(InetAddresses.forString(ipRangeArr[0]));
            int highIpInt = InetAddresses.coerceToInteger(InetAddresses.forString(ipRangeArr[1]));
            for (int i = lowIpInt; i <= highIpInt; i++) {
                addToTrie(trie, getIpStringFromIpInt(i), port);
            }
        }
    }

    /**
     * Add a single IP address and port to the trie
     */
    private void addToTrie(final AddressNode trie, final String ipString, final String port) {
        final String ipInBinaryString = getBinaryStringFromIp(ipString);
        int i = 0;
        AddressNode curr = trie;
        while (i < ipInBinaryString.length()) {
            int node = ipInBinaryString.charAt(i) - '0';
            if (curr.childArr[node] == null) {
                curr.childArr[node] = new AddressNode(node, false);
            }
            curr = curr.getChildArr()[node];
            if (i == ipInBinaryString.length() - 1) {
                curr.setEnd(true);
                if (curr.ports == null) {
                    curr.ports = new ArrayList<>();
                }
            }
            i++;
        }
        mergePortInExistingList(port, curr.getPorts());
    }

    /**
     * Returns a 32 bit binary number in string representation representing the given ipAddress
     */
    private String getBinaryStringFromIp(final String ipAddress) {
        String[] addresses = ipAddress.split(DOT_DELIMITER);
        StringBuilder sb = new StringBuilder();
        for (String address : addresses) {
            sb.append(Integer.toBinaryString(Integer.parseInt(address)));
        }
        return sb.toString();
    }

    /**
     * Returns the long representation of an ip address in the form of InetAddress
     */
    private long getLongFromInetAddress(InetAddress ip) {
        byte[] bytes = ip.getAddress();
        long result = 0;
        for (byte octet : bytes) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }

    /**
     * Returns the string representation of the ip address in int format
     */
    private String getIpStringFromIpInt(final int ipInInt) {
        return InetAddresses.toAddrString(InetAddresses.fromInteger(ipInInt));
    }

    /**
     * Merge new port (range) into the existing list
     */
    private void mergePortInExistingList(final String port, final List<Interval> existingPortList) {
        int begin, end;

        if (port.contains(RANGE_DELIMITER)) {
            String[] rangeArr = port.split(RANGE_DELIMITER);
            begin = Integer.parseInt(rangeArr[0]);
            end = Integer.parseInt(rangeArr[1]);
        } else {
            begin = Integer.parseInt(port);
            end = begin;
        }

        Interval portInterval = new Interval(begin, end);
        if (existingPortList.isEmpty()) {
            existingPortList.add(portInterval);
            return;
        }

        if (existingPortList.contains(portInterval)) {
            return;
        }

        // else merge in the existing list
        int index = 0;
        for (int i = 0; i < existingPortList.size(); i++) {
            Interval current = existingPortList.get(i);
            if (i + 1 < existingPortList.size()) {
                if (current.getEnd() >= begin - 1) {
                    if (existingPortList.get(i + 1).getStart() > end + 1) {
                        current.setStart(Math.min(begin, current.getStart()));
                        current.setEnd(Math.max(end, current.getEnd()));
                        return;
                    } else {
                        index = i;
                        break;
                    }
                } else if (existingPortList.get(i + 1).getStart() > end + 1) {
                    index = i;
                    break;
                }
            } else if (current.getEnd() >= begin - 1) {
                current.setStart(Math.min(begin, current.getStart()));
                current.setEnd(Math.max(end, current.getEnd()));
                return;
            } else {
                index = i;
            }
        }

        Interval interval = new Interval(begin, end);
        if (index == existingPortList.size() - 1) {
            existingPortList.add(interval);
        } else if (existingPortList.get(index).getEnd() < begin - 1 && existingPortList.get(index + 1).getStart() > end + 1) {
            existingPortList.add(index + 1, interval);
        } else {
            Interval deleted = existingPortList.remove(index + 1);
            Interval current = existingPortList.get(index);
            current.setStart(Math.min(begin, Math.min(current.getStart(), deleted.getStart())));
            current.setEnd(Math.max(end, Math.max(current.getEnd(), deleted.getEnd())));
        }

    }

    /**
     * takes exactly four arguments and returns a boolean: true, if there exists a rule in the file
     * that this object was initialized with that allows traffic with
     * these particular properties, and false otherwise
     */
    public boolean accept_packet(final String direction, final String protocol, final int port, final String ip_address) {
        switch (direction) {
            case INBOUND:
                if (TCP.equals(protocol)) {
                    return shouldAccept(inTcpTrie, port, ip_address);
                } else {
                    return shouldAccept(inUdpTrie, port, ip_address);
                }
            case OUTBOUND:
                if (TCP.equals(protocol)) {
                    return shouldAccept(outTcpTrie, port, ip_address);
                } else {
                    return shouldAccept(outUdpTrie, port, ip_address);
                }
        }
        return false;
    }

    /**
     * Return true if the network packet is allowed to move
     */
    private boolean shouldAccept(final AddressNode trie, final int port, final String ipString) {
        final String ipStringInBinary = getBinaryStringFromIp(ipString);
        int i = 0;
        AddressNode curr = trie;
        while (i < ipStringInBinary.length()) {
            int node = ipStringInBinary.charAt(i) - '0';
            if (curr.childArr[node] == null) {
                return false;
            }
            curr = curr.childArr[node];
            i++;
        }
        return curr.isEnd() && containsPort(curr.getPorts(), port);
    }

    /**
     * Return true if the given port is already present in the  existing list
     */
    private boolean containsPort(List<Interval> existingPortList, int port) {
        if (existingPortList == null) {
            return false;
        }

        for (int i = 0; i < existingPortList.size(); i++) {
            Interval current = existingPortList.get(i);
            if (i + 1 < existingPortList.size() && port > current.getEnd() && port < existingPortList.get(i + 1).getStart()) {
                return false;
            }
            if (port >= current.getStart() && port <= current.getEnd()) {
                return true;
            }
        }
        return false;
    }

    /**
     * The trie node structure to contain the binary information of IP address and ports.
     */
    @Data
    private class AddressNode {
        private int address;
        private boolean isEnd;
        private List<Interval> ports;
        private AddressNode[] childArr;

        private AddressNode(final int address, final boolean isEnd) {
            this.address = address;
            this.isEnd = isEnd;

            if (isEnd) {
                this.ports = new ArrayList<>();
            } else {
                this.childArr = new AddressNode[2];
            }
        }
    }

    /**
     * Port Interval class contains the start to the end of the port range.
     */
    @Data
    private class Interval {
        private int start;
        private int end;

        private Interval(final int begin, final int end) {
            this.start = begin;
            this.end = end;
        }
    }
}
