import {Libc} from "../../../libs/Libc";
import {AllianceManager} from "../../../logic/alliance/AllianceManager";
import {HashTagCodeGenerator} from "../../../titan/logic/util/HashTagCodeGenerator";
import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class SpectateCommand extends MainCommand {
    getCommandRegexp() {
        return /spectate/i;
    }

    execute(args: Array<string | number>) {
        let hashtag = args[0];
        let accountId = HashTagCodeGenerator.toId(hashtag as string);

        let ptr = Libc.malloc(8);
        ptr.writeInt(accountId[0]);
        ptr.add(4).writeInt(accountId[1]);

        AllianceManager.startSpectate(ptr);

        return "";
    }

    getPermission() {
        return Permissions.EVERYONE;
    }

    getCommandInformation() {
        return {
            name: "spectate",
            desc: "Spectate command",
            isHidden: false
        };
    }
}