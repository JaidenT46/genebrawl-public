import {PiranhaMessage} from "../PiranhaMessage";

export class ClaimVouncherFailedMessageReceived extends PiranhaMessage {
    constructor(instance: NativePointer) {
        super(instance);
    }
}