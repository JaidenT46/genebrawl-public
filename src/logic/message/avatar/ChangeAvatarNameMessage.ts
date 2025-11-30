import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";
import {PiranhaMessage} from "../PiranhaMessage";

const nameOffset = 144;
const nameSetByUserOffset = 152;

export class ChangeAvatarNameMessage extends PiranhaMessage {
    constructor() {
        let instance = LogicLaserMessageFactory.createMessage(10212);

        super(instance);
    }

    setName(name: string) {
        this.instance.add(nameOffset).writePointer(name.scptr());
    }

    setNameSetByUser(nameSetByUser: boolean) {
        this.instance.add(nameSetByUserOffset).writeU8(Number(nameSetByUser));
    }
}