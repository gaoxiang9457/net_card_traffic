package com.example.demo;

/**
 * @Description
 * @auther gaojunfeng
 * @create 2019-11-08
 */

import com.sun.jna.Platform;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 监听网卡打印访问量 port=xx  ip=aa.bb.cc
 */
@SpringBootApplication
public class App {
    private static final Logger logger = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) throws PcapNativeException, NotOpenException, FileNotFoundException {

        List<PcapNetworkInterface> allDevs1 = Pcaps.findAllDevs();
        allDevs1.forEach(x -> logger.info(x.toString()));

        List<PcapNetworkInterface> allDevs = allDevs1.stream()
                .filter(x -> !x.isLoopBack()/* && x.isUp() */ && x.getAddresses().size() > 0
                                && x.getAddresses().stream().anyMatch(y -> y.getNetmask() != null && !y.getAddress().getHostAddress().startsWith("0."))
//                        && x.getLinkLayerAddresses().size() > 0
                                && waitForPing(x)
                ).collect(Collectors.toList());

        Map<String, String> argMap = new HashMap<>();
        if (args.length > 0) {
            argMap = Arrays.asList(args).stream().map(x -> x.split("="))
                    .filter(y -> Strings.isNotBlank(y[0]) && Strings.isNotBlank(y[1]))
                    .collect(Collectors.toMap(z -> z[0], z -> z[1]));
        }

        String port = argMap.get("port");
        port = Strings.isBlank(port) ? "80" : port;
        PcapNetworkInterface device = null;
        do {
            if (allDevs.size() > 1) {
                String ip = argMap.get("ip");
                if (ip != null) {
                    Optional<PcapNetworkInterface> any = allDevs.stream()
                            .filter(x -> x.getAddresses().stream()
                                    .anyMatch(y -> y.getAddress().getHostAddress().startsWith(ip))).findAny();
                    if (any.isPresent()) {
                        device = any.get();
                        break;
                    } else {
                        logger.info("no matched ip found");
                        return;
                    }
                }
                logger.info("too many ip  found ,set ip prefix first :\n" + allDevs.stream().map(x -> x.getName()).collect(Collectors.toList()));

                return;
            } else {
                device = allDevs.get(0);
            }
        } while (false);

        logger.info("You chose: " + device);

        if (device == null) {
            logger.info("No device chosen.");
            System.exit(1);
        }

        Optional<PcapAddress> any = device.getAddresses().stream().filter(x -> x.getNetmask() != null).findAny();
        if (!any.isPresent()) {
            return;
        }
        String ipv4 = any.orElseGet(null).getAddress().getHostAddress();

//        bpfExpression demo
//        https://hackertarget.com/tcpdump-examples/

        String bpfExpression = argMap.get("exp") == null ? ("  (  (dst port " + port + " and dst host " + ipv4 + ") " +
                "or (src port " + port + " and src host " + ipv4 + ") )  " +
                "and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0 ) " //BODY
                + "and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450 " + //HTTP
                "or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 " +//GET
                "or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 " +//POST
                "or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420 " +//PUT
                "or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454C45) "//DELE
        )
                : argMap.get("exp");

//        String response = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450";
//        bpfExpression = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        logger.info("bpfExpression:" + bpfExpression);
 
 
        int readTimeout = 50; // in milliseconds
        final PcapHandle handle = device.openLive(70, PromiscuousMode.NONPROMISCUOUS, readTimeout);
        PcapDumper dumper = handle.dumpOpen("out.pcap");

        // Set a filter to only listen for tcp packets on port 80 (HTTP)
        handle.setFilter(bpfExpression, BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = packet -> {
//             Print packet information to screen
//            logger.info(handle.getTimestampPrecision());
//            logger.info(packet);

            // Dump packets to file
//            try {
//                dumper.dump(packet, packet.getTimestamp());
//            } catch (NotOpenException e) {
//                e.printStackTrace();
//            }


            IpV4Packet ip4 = packet.get(IpV4Packet.class);
            if (null != ip4) {
                String src = ip4.getHeader().getSrcAddr().getHostAddress();
                String dst = ip4.getHeader().getDstAddr().getHostAddress();
                byte[] data = ip4.getPayload().getRawData();
                String msg = new String(data, 20, 15);
 
                if (msg.startsWith("HTTP")) {
                    logger.info("response src:" + src + " dst:" + dst + "\t" + msg);
                } else {
                    logger.info("request src:" + src + " dst:" + dst + "\t" + msg);
                }
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Print out handle statistics
        PcapStat stats = handle.getStats();
        logger.info("Packets received: " + stats.getNumPacketsReceived());
        logger.info("Packets dropped: " + stats.getNumPacketsDropped());
        logger.info("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        // Supported by WinPcap only
        if (Platform.isWindows()) {
            logger.info("Packets captured: " + stats.getNumPacketsCaptured());
        }

        // Cleanup when complete
        dumper.close();
        handle.close();

    }


    private static boolean waitForPing(PcapNetworkInterface nif) {

        logger.info(nif.getName() + " (" + nif.getDescription() + ")");
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() != null) {
                boolean reachable = false;
                try {
                    reachable = addr.getAddress().isReachable(50);
                } catch (IOException e) {
                    continue;
                }
                if (reachable) {
                    return true;
                }
            }
        }
        return false;
    }
}