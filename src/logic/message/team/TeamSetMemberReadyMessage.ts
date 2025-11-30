import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

const stateOffset = 144;

export class TeamSetMemberReadyMessage extends PiranhaMessage {
    constructor(status: boolean = false, message?: NativePointer) {
        if (!message)
            message = LogicLaserMessageFactory.createMessage(14355);

        message.add(stateOffset).writeU8(Number(status));

        super(message);
    }
}