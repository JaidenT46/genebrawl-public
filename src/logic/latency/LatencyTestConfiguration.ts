import {LatencyManager} from "../../laser/client/network/LatencyManager";
import {Libg} from "../../libs/Libg";

const maxTestsOffset = 4;

const LatencyTestConfiguration_decode = new NativeFunction( // in decode 49001 (StartLatencyTestRequestMessage)
    Libg.offset(0xA9CAF4, 0x9F7674), 'void', ['pointer', 'pointer']
); 

export class LatencyTestConfiguration {
    static patch() {
        Interceptor.replace(LatencyTestConfiguration_decode, new NativeCallback(function(self, stream) {
            LatencyTestConfiguration_decode(self, stream);

            if (LatencyManager.shouldSpoofResult()) {
                self.add(maxTestsOffset).writeInt(1);
            }
        }, 'void', ['pointer', 'pointer']));
    }
}