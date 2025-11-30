import {PiranhaMessage} from "../PiranhaMessage";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";

const playerIdOffset = 144;
const brawlTvOffset = 152;

export class StartSpectateMessage extends PiranhaMessage {
    constructor(playerId: NativePointer, status: boolean) {
        const instance = LogicLaserMessageFactory.createMessage(14104);

        instance.add(playerIdOffset).writePointer(playerId);
        instance.add(brawlTvOffset).writeU8(Number(status));

        super(instance);
    }
}