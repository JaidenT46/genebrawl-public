import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

const statusOffset = 144;

export class TeamMemberStatusMessage extends PiranhaMessage {
    constructor(status: number = 0, message?: NativePointer) {
        if (!message)
            message = LogicLaserMessageFactory.createMessage(14361);

        message.add(statusOffset).writeInt(status);

        super(message);
    }
}