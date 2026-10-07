package io.nekohasekai.sagernet.fmt.bepass;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

/**
 * Native bepass profile (TLS ClientHello-fragmentation DPI bypass).
 * When active, the bepass engine owns the Android TUN directly and
 * sing-box is not started.
 */
public class BepassBean extends AbstractBean {

    // TLS fragmentation parameters
    public Integer tlsHeaderLength;
    public Boolean tlsPaddingEnabled;
    public Integer tlsPaddingSizeMin;
    public Integer tlsPaddingSizeMax;
    public Integer chunksBeforeSniMin;
    public Integer chunksBeforeSniMax;
    public Integer sniChunksMin;
    public Integer sniChunksMax;
    public Integer chunksAfterSniMin;
    public Integer chunksAfterSniMax;
    public Integer delayBetweenChunksMin;
    public Integer delayBetweenChunksMax;

    // DNS
    public Integer dnsCacheTtl;
    public Integer dnsRequestTimeout;
    public String remoteDnsAddr;
    public Boolean enableDnsFragmentation;

    // Cloudflare worker
    public Boolean workerEnabled;
    public String workerAddress;
    public String workerIpPortAddress;
    public Boolean workerDnsOnly;

    // Advanced
    public Boolean enableLowLevelSockets;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (tlsHeaderLength == null) tlsHeaderLength = 5;
        if (tlsPaddingEnabled == null) tlsPaddingEnabled = false;
        if (tlsPaddingSizeMin == null) tlsPaddingSizeMin = 40;
        if (tlsPaddingSizeMax == null) tlsPaddingSizeMax = 80;
        if (chunksBeforeSniMin == null) chunksBeforeSniMin = 2000;
        if (chunksBeforeSniMax == null) chunksBeforeSniMax = 2000;
        if (sniChunksMin == null) sniChunksMin = 1;
        if (sniChunksMax == null) sniChunksMax = 2;
        if (chunksAfterSniMin == null) chunksAfterSniMin = 2000;
        if (chunksAfterSniMax == null) chunksAfterSniMax = 2000;
        if (delayBetweenChunksMin == null) delayBetweenChunksMin = 10;
        if (delayBetweenChunksMax == null) delayBetweenChunksMax = 20;

        if (dnsCacheTtl == null) dnsCacheTtl = 3000000;
        if (dnsRequestTimeout == null) dnsRequestTimeout = 10;
        if (remoteDnsAddr == null) remoteDnsAddr = "https://1.1.1.1/dns-query";
        if (enableDnsFragmentation == null) enableDnsFragmentation = false;

        if (workerEnabled == null) workerEnabled = false;
        if (workerAddress == null) workerAddress = "";
        if (workerIpPortAddress == null) workerIpPortAddress = "";
        if (workerDnsOnly == null) workerDnsOnly = false;

        if (enableLowLevelSockets == null) enableLowLevelSockets = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(1);
        super.serialize(output);
        output.writeInt(tlsHeaderLength);
        output.writeBoolean(tlsPaddingEnabled);
        output.writeInt(tlsPaddingSizeMin);
        output.writeInt(tlsPaddingSizeMax);
        output.writeInt(chunksBeforeSniMin);
        output.writeInt(chunksBeforeSniMax);
        output.writeInt(sniChunksMin);
        output.writeInt(sniChunksMax);
        output.writeInt(chunksAfterSniMin);
        output.writeInt(chunksAfterSniMax);
        output.writeInt(delayBetweenChunksMin);
        output.writeInt(delayBetweenChunksMax);
        output.writeInt(dnsCacheTtl);
        output.writeInt(dnsRequestTimeout);
        output.writeString(remoteDnsAddr);
        output.writeBoolean(enableDnsFragmentation);
        output.writeBoolean(workerEnabled);
        output.writeString(workerAddress);
        output.writeString(workerIpPortAddress);
        output.writeBoolean(workerDnsOnly);
        output.writeBoolean(enableLowLevelSockets);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        if (version >= 1) {
            tlsHeaderLength = input.readInt();
            tlsPaddingEnabled = input.readBoolean();
            tlsPaddingSizeMin = input.readInt();
            tlsPaddingSizeMax = input.readInt();
            chunksBeforeSniMin = input.readInt();
            chunksBeforeSniMax = input.readInt();
            sniChunksMin = input.readInt();
            sniChunksMax = input.readInt();
            chunksAfterSniMin = input.readInt();
            chunksAfterSniMax = input.readInt();
            delayBetweenChunksMin = input.readInt();
            delayBetweenChunksMax = input.readInt();
            dnsCacheTtl = input.readInt();
            dnsRequestTimeout = input.readInt();
            remoteDnsAddr = input.readString();
            enableDnsFragmentation = input.readBoolean();
            workerEnabled = input.readBoolean();
            workerAddress = input.readString();
            workerIpPortAddress = input.readString();
            workerDnsOnly = input.readBoolean();
            enableLowLevelSockets = input.readBoolean();
        }
    }

    @Override
    public boolean canTCPing() {
        return false;
    }

    @NotNull
    @Override
    public String getHash() {
        return buildTypedHash("bepass");
    }

    @NotNull
    @Override
    public BepassBean clone() {
        return KryoConverters.deserialize(new BepassBean(), KryoConverters.serialize(this));
    }

    public static final Creator<BepassBean> CREATOR = new CREATOR<BepassBean>() {
        @NonNull
        @Override
        public BepassBean newInstance() {
            return new BepassBean();
        }

        @Override
        public BepassBean[] newArray(int size) {
            return new BepassBean[size];
        }
    };

}
