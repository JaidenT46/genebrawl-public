import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

export class TeamChatMessage extends PiranhaMessage {
    static messageOffset = 144;

    constructor(instance?: NativePointer) {
        if (!instance)
            instance = LogicLaserMessageFactory.createMessage(14049);

        super(instance);
    }

    getMessage(): string {
        return this.instance.add(TeamChatMessage.messageOffset).fromsc();
    }

    setMessage(message: string) {
        this.instance.add(TeamChatMessage.messageOffset).scptr(message);
    }
}