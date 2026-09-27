package io.nekohasekai.sagernet.fmt.shadowsocks;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import moe.matsuri.nb4a.utils.JavaUtil;

public class ShadowsocksBean extends AbstractBean {

    public String method;
    public String password;
    public String plugin;

    public Boolean sUoT;

    public Boolean enableMux;
    public Boolean muxPadding;
    public Integer muxType;
    public Integer muxConcurrency;  // max_streams
    public Integer muxMode;         // 0: max_streams, 1: connections
    public Integer muxMaxConnections;
    public Integer muxMinStreams;
    public Boolean muxBrutal;
    public Integer muxBrutalUpMbps;
    public Integer muxBrutalDownMbps;

    // SNI Spoofing (root sidecar, per-profile)
    public Boolean sniSpoofEnabled;
    public String sniSpoofConnect;   // host:port override, blank = server address
    public String sniSpoofFakeSni;   // decoy SNI, blank = sidecar default
    public String sniSpoofUtls;      // utls fingerprint, blank = chrome
    public String sniSpoofInjector;  // injector mode, blank = active

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (JavaUtil.isNullOrBlank(method)) method = "aes-256-gcm";
        if (method == null) method = "";
        if (password == null) password = "";
        if (plugin == null) plugin = "";
        if (sUoT == null) sUoT = false;

        if (enableMux == null) enableMux = false;
        if (muxPadding == null) muxPadding = false;
        if (muxType == null) muxType = 0;
        if (muxConcurrency == null) muxConcurrency = 8;
        if (muxMode == null) muxMode = 0;
        if (muxMaxConnections == null) muxMaxConnections = 4;
        if (muxMinStreams == null) muxMinStreams = 4;
        if (muxBrutal == null) muxBrutal = false;
        if (muxBrutalUpMbps == null) muxBrutalUpMbps = 100;
        if (muxBrutalDownMbps == null) muxBrutalDownMbps = 100;

        if (sniSpoofEnabled == null) sniSpoofEnabled = false;
        if (sniSpoofConnect == null) sniSpoofConnect = "";
        if (sniSpoofFakeSni == null) sniSpoofFakeSni = "";
        if (sniSpoofUtls == null) sniSpoofUtls = "";
        if (sniSpoofInjector == null) sniSpoofInjector = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(6);
        super.serialize(output);
        output.writeString(method);
        output.writeString(password);
        output.writeString(plugin);
        output.writeBoolean(sUoT);
        // v3
        output.writeBoolean(enableMux);
        output.writeBoolean(muxPadding);
        output.writeInt(muxType);
        output.writeInt(muxConcurrency);
        // v4
        output.writeInt(muxMode);
        output.writeInt(muxMaxConnections);
        output.writeInt(muxMinStreams);
        // v5
        output.writeBoolean(muxBrutal);
        output.writeInt(muxBrutalUpMbps);
        output.writeInt(muxBrutalDownMbps);
        // v6: SNI Spoofing (root sidecar, per-profile)
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
        method = input.readString();
        password = input.readString();
        plugin = input.readString();
        sUoT = input.readBoolean();

        if (version >= 3) {
            enableMux = input.readBoolean();
            muxPadding = input.readBoolean();
            muxType = input.readInt();
            muxConcurrency = input.readInt();
        }
        // v4
        if (version >= 4) {
            muxMode = input.readInt();
            muxMaxConnections = input.readInt();
            muxMinStreams = input.readInt();
        }
        // v5
        if (version >= 5) {
            muxBrutal = input.readBoolean();
            muxBrutalUpMbps = input.readInt();
            muxBrutalDownMbps = input.readInt();
        }
        // v6: SNI Spoofing (root sidecar, per-profile)
        if (version >= 6) {
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
        return buildTypedHash("shadowsocks");
    }

    @NotNull
    @Override
    public ShadowsocksBean clone() {
        return KryoConverters.deserialize(new ShadowsocksBean(), KryoConverters.serialize(this));
    }

    public static final Creator<ShadowsocksBean> CREATOR = new CREATOR<ShadowsocksBean>() {
        @NonNull
        @Override
        public ShadowsocksBean newInstance() {
            return new ShadowsocksBean();
        }

        @Override
        public ShadowsocksBean[] newArray(int size) {
            return new ShadowsocksBean[size];
        }
    };
}
