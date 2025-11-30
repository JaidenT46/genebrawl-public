import {LogicVersion} from "../../logic/LogicVersion";
import {MainCommand} from "./MainCommand";
import {Permissions} from "./Permissions";
import * as commands from "./cmds/index";

const commandModules: { [key: string]: typeof MainCommand; } = commands;

export class CommandsHandler {
    static commands: Array<MainCommand> = [];
    static isLoaded: Boolean = false;

    static load() {
        if (CommandsHandler.isLoaded) {
            return console.log("CommandsHandler.load:", "Commands already was loaded!");
        }

        for (const key in commandModules) {
            if (Object.prototype.hasOwnProperty.call(commandModules, key)) {
                const CommandClass = commandModules[key];
                const commandInstance = new CommandClass(); // Instantiate the command
                CommandsHandler.commands.push(commandInstance);
            }
        }

        CommandsHandler.isLoaded = true;

        console.log("CommandsHandler.load:", "Loaded", this.commands.length, "commands!");
    }

    static execute(search: string, args: Array<string | number>) {
        if (!CommandsHandler.isLoaded) {
            console.log("CommandsHandler.execute:", "Commands wasn't loaded! Loading...");
            CommandsHandler.load();
        }

        const command = CommandsHandler.commands.find(cmd => cmd.getCommandRegexp().test(search));

        if (!command) {
            return "NO_COMMAND_DEFINED";
        }

        switch (command.getPermission()) {
            case Permissions.VIP:
                if (!LogicVersion.isVip() && !LogicVersion.isDeveloperBuild())
                    return "NO_PERMISSIONS";
                break;
            case Permissions.DEVELOPER:
                if (!LogicVersion.isDeveloperBuild())
                    return "NO_COMMAND_DEFINED";
                break;
            case Permissions.NDA:
                if (!LogicVersion.isDeveloperBuild() && !LogicVersion.isNDA)
                    return "NO_COMMAND_DEFINED";
                break;
        }

        return command.execute(args);
    }
}