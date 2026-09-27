package io.nekohasekai.sagernet.fmt.socks;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class SOCKSBean extends AbstractBean {

    public Integer protocol;

    public Boolean sUoT;

    public int protocolVersion() {
        switch (protocol) {
            case 0:
            case 1:
                return 4;
            default:
                return 5;
        }
    }

    public String protocolName() {
        switch (protocol) {
            case 0:
                return "SOCKS4";
            case 1:
                return "SOCKS4A";
            default:
                return "SOCKS5";
        }
    }

    public String protocolVersionName() {
        switch (protocol) {
            case 0:
                return "4";
            case 1:
                return "4a";
            default:
                return "5";
        }
    }

    public String username;
    public String password;

    // SNI Spoofing (root sidecar, per-profile)
    public Boolean sniSpoofEnabled;
    public String sniSpoofConnect;   // host:port override, blank = server address
    public String sniSpoofFakeSni;   // decoy SNI, blank = sidecar default
    public String sniSpoofUtls;      // utls fingerprint, blank = chrome
    public String sniSpoofInjector;  // injector mode, blank = active

    public static final int PROTOCOL_SOCKS4 = 0;
    public static final int PROTOCOL_SOCKS4A = 1;
    public static final int PROTOCOL_SOCKS5 = 2;

    @Override
    public String network() {
        if (protocol < PROTOCOL_SOCKS5) return "tcp";
        return super.network();
    }

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (protocol == null) protocol = PROTOCOL_SOCKS5;
        if (username == null) username = "";
        if (password == null) password = "";
        if (sUoT == null) sUoT = false;

        if (sniSpoofEnabled == null) sniSpoofEnabled = false;
        if (sniSpoofConnect == null) sniSpoofConnect = "";
        if (sniSpoofFakeSni == null) sniSpoofFakeSni = "";
        if (sniSpoofUtls == null) sniSpoofUtls = "";
        if (sniSpoofInjector == null) sniSpoofInjector = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(3);
        super.serialize(output);
        output.writeInt(protocol);
        output.writeString(username);
        output.writeString(password);
        output.writeBoolean(sUoT);
        // v3: SNI Spoofing (root sidecar, per-profile)
        output.writeBoolean(sniSpoofEnabled);
        output.writeString(sniSpoofConnect);
        output.writeString(sniSpoofFakeSni);
        output.writeString(sniSpoofUtls);
        output.writeString(sniSpoofInjector);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        if (version >= 1) {
            protocol = input.readInt();
        }
        username = input.readString();
        password = input.readString();
        if (version >= 2) {
            sUoT = input.readBoolean();
        }
        // v3: SNI Spoofing (root sidecar, per-profile)
        if (version >= 3) {
            sniSpoofEnabled = input.readBoolean();
            sniSpoofConnect = input.readString();
            sniSpoofFakeSni = input.readString();
            sniSpoofUtls = input.readString();
            sniSpoofInjector = input.readString();
        }
    }

    @NotNull
    @Override
    public String getHash() {
        return buildTypedHash("socks");
    }

    @NotNull
    @Override
    public SOCKSBean clone() {
        return KryoConverters.deserialize(new SOCKSBean(), KryoConverters.serialize(this));
    }

    public static final Creator<SOCKSBean> CREATOR = new CREATOR<SOCKSBean>() {
        @NonNull
        @Override
        public SOCKSBean newInstance() {
            return new SOCKSBean();
        }

        @Override
        public SOCKSBean[] newArray(int size) {
            return new SOCKSBean[size];
        }
    };

}
