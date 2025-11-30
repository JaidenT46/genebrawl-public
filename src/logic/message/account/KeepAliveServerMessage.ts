import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

export class KeepAliveServerMessage extends PiranhaMessage {
    constructor() {
        super(LogicLaserMessageFactory.createMessage(20108));
    }
}