import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

const unknownBooleanOffset = 144;

export class GoHomeFromOfflinePractiseMessage extends PiranhaMessage {
    constructor(unknownBoolean: boolean) {
        const instance = LogicLaserMessageFactory.createMessage(17750);

        instance.add(unknownBooleanOffset).writeU8(Number(unknownBoolean));

        super(instance);
    }
}