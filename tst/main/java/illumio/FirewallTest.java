package illumio;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FirewallTest {

    private static final String INBOUND = "inbound";
    private static final String OUTBOUND = "outbound";
    private static final String TCP = "tcp";
    private static final String UDP = "udp";

    // class under test
    Firewall fw;


    @Before
    public void setUp() throws Exception {
        // name of the input csv file
        this.fw = new Firewall("testCSV.csv");
    }

    /**
     * happy path
     */
    @Test
    public void accept_packet_accept() {
        assertTrue(fw.accept_packet(INBOUND, TCP, 8080, "255.255.255.0"));
        assertTrue(fw.accept_packet(INBOUND, TCP, 80, "0.0.0.0"));
        assertTrue(fw.accept_packet(INBOUND, UDP, 1, "0.0.0.0"));
        assertTrue(fw.accept_packet(INBOUND, TCP, 8080, "255.255.255.255"));
        assertTrue(fw.accept_packet(OUTBOUND, TCP, 65535, "0.0.0.255"));
        assertTrue(fw.accept_packet(INBOUND, TCP, 65535, "0.255.255.255"));
        assertTrue(fw.accept_packet(OUTBOUND, TCP, 30000, "192.168.10.10"));
        assertTrue(fw.accept_packet(INBOUND, TCP, 60001, "0.255.0.1"));
        assertTrue(fw.accept_packet(OUTBOUND, TCP, 10234, "192.168.10.11"));
        assertTrue(fw.accept_packet(OUTBOUND, TCP, 20002, "192.168.10.20"));
        assertTrue(fw.accept_packet(OUTBOUND, UDP, 1500, "52.12.48.92"));
    }

    @Test
    public void accept_packet_protocol_reject() {
        assertFalse(fw.accept_packet(OUTBOUND, TCP, 1000, "192.168.48.92"));
        assertFalse(fw.accept_packet(INBOUND, UDP, 8080, "255.255.255.1"));
    }

    @Test
    public void accept_packet_direction_reject() {
        assertFalse(fw.accept_packet(OUTBOUND, TCP, 80, "192.168.1.2"));
        assertFalse(fw.accept_packet(INBOUND, TCP, 10000, "192.168.10.11"));
    }

    @Test
    public void accept_packet_port_reject() {
        assertFalse(fw.accept_packet(OUTBOUND, TCP, 20001, "192.168.10.11"));
        assertFalse(fw.accept_packet(INBOUND, UDP, 24, "52.12.48.92"));
        assertFalse(fw.accept_packet(INBOUND, TCP, 5001, "0.0.0.0"));
    }

    @Test
    public void accept_packet_ipAddress_reject() {
        assertFalse(fw.accept_packet(OUTBOUND, UDP, 500, "52.12.48.96"));
        assertFalse(fw.accept_packet(OUTBOUND, TCP, 65535, "0.0.1.0"));
        assertFalse(fw.accept_packet(INBOUND, TCP, 8000, "245.255.255.255"));
    }
}
