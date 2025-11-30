import {LogicCommand} from "./LogicCommand";
import {LogicSelectSkinCommand} from "./LogicSelectSkinCommand";

export class LogicCommandManager {
    static createCommand(command: NativePointer): LogicCommand {
        let commandType = LogicCommand.getCommandType(command);

        switch (commandType) {
            case 506: return new LogicSelectSkinCommand(command);

            default: return new LogicCommand(command);
        }
    }
}