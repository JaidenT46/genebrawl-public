import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

export class StopSpectateMessage extends PiranhaMessage {
    constructor() {
        super(LogicLaserMessageFactory.createMessage(14107));
    }
}