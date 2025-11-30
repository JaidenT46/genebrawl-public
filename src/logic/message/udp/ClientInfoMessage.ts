import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

export class ClientInfoMessage extends PiranhaMessage {
    constructor(message?: NativePointer) {
        if (!message)
            message = LogicLaserMessageFactory.createMessage(10177);

        super(message);
    }
}