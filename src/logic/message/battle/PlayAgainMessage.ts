import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

const statusOffset = 144;

export class PlayAgainMessage extends PiranhaMessage {
    constructor(status: boolean) {
        const instance = LogicLaserMessageFactory.createMessage(14177);

        instance.add(statusOffset).writeU8(Number(status));

        super(instance);
    }
}