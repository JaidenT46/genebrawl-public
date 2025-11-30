import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

const playerIdOffset = 144;

export class GetPlayerProfileMessage extends PiranhaMessage {
    constructor(id: number[]) {
        const instance = LogicLaserMessageFactory.createMessage(15081);

        instance.add(playerIdOffset).writeInt(id[0]);
        instance.add(playerIdOffset).add(4).writeInt(id[1]);

        super(instance);
    }
}