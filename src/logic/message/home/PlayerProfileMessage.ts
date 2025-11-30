import {PiranhaMessage} from "../PiranhaMessage";
import {PlayerProfile} from "../../home/PlayerProfile";

const playerProfileOffset = 144;

export class PlayerProfileMessage extends PiranhaMessage {
    constructor(instance: NativePointer) {
        super(instance);
    }

    getPlayerProfile(): PlayerProfile {
        return new PlayerProfile(
            this.instance.add(playerProfileOffset).readPointer()
        );
    }
}