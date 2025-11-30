import {LatencyManager} from "../../../laser/client/network/LatencyManager";
import {Libg} from "../../../libs/Libg";
import {PiranhaMessage} from "../PiranhaMessage";

const regionIdOffset = 144;
const pingOffset = 148;

const LatencyTestResultMessage_encode = new NativeFunction( // 39001
    Libg.offset(0xA9CEC8, 0x9F7A24), 'void', ['pointer']
);

export class LatencyTestResultMessage extends PiranhaMessage {
    static patch() {
        Interceptor.replace(LatencyTestResultMessage_encode, new NativeCallback(function (message) {
            let piranha = new LatencyTestResultMessage(message);

            if (LatencyManager.shouldSpoofResult()) {
                piranha.spoofPing();
            }

            piranha.setUnknown();

            LatencyTestResultMessage_encode(message);
        }, 'void', ['pointer']));
    }

    spoofPing() {
        let regionId = LatencyManager.getSelectedRegion();

        if (this.getRegionId() != regionId) {
            this.setPing(this.getPing() + 1000);
        }
    }

    getRegionId(): number {
        return this.instance.add(regionIdOffset).readInt();
    }

    getPing(): number {
        return this.instance.add(pingOffset).readInt();
    }

    setPing(ping: number) {
        this.instance.add(pingOffset).writeInt(ping);
    }

    setUnknown() {
        this.instance.add(152).writeInt(5);
        this.instance.add(156).writeInt(5);
        this.instance.add(160).writeInt(10);
    }
}