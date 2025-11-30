import {Configuration} from "../../Configuration";
import {MainCommand} from "../MainCommand";
import {Permissions} from "../Permissions";

export class LobbyInfoCommand extends MainCommand {
    getCommandRegexp() {
        return /lobbyinfo/i;
    }

    execute(args: Array<string | number>) {
        Configuration.showLobbyInfo = !Configuration.showLobbyInfo;

        return "";
    }

    getPermission() {
        return Permissions.NDA;
    }

    getCommandInformation() {
        return {
            name: "lobbyinfo",
            desc: "hide/show lobby info",
            isHidden: true
        };
    }
}