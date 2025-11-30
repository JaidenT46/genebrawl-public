import {PiranhaMessage} from "../PiranhaMessage";
import {LogicClientAvatar} from "../../avatar/LogicClientAvatar";

const logicClientHomeOffset = 144;
const logicClientAvatarOffset = 152;

const logicConfDataOffset = 32;

export class OwnHomeDataMessage extends PiranhaMessage {
    constructor(instance: NativePointer) {
        super(instance);
    }

    getClientHome() {
        return this.instance.add(logicClientHomeOffset).readPointer();
    }

    getConfData(): NativePointer {
        return this.getClientHome().add(logicConfDataOffset).readPointer();
    }

    getClientAvatar() {
        return new LogicClientAvatar(
            this.instance.add(logicClientAvatarOffset).readPointer()
        );
    }
}