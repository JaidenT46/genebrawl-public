import {Configuration} from "../../../gene/Configuration";
import {DebugMenu} from "../../../gene/debug/DebugMenu";
import {EDebugCategory} from "../../../gene/debug/DebugMenuCategory";
import {LocalizationManager} from "../../../gene/localization/index";
import {LatencyData} from "../../../logic/latency/LatencyData";
import {LatencyTestConfiguration} from "../../../logic/latency/LatencyTestConfiguration";
import {LatencyTestResultMessage} from "../../../logic/message/latency/LatencyTestResultMessage";
import {TriggerStartLatencyTestMessage} from "../../../logic/message/latency/TriggerStartLatencyTestMessage";
import {GUI} from "../../../titan/flash/gui/GUI";
import {MessageManager} from "./MessageManager";

const maxServersCount = 19;

export class LatencyManager {
    static selectedRegionId: number = -1;
    static goingToSelectRegionId: number = -1;
    static triggeringTests: boolean = false;

    static patch() {
        LatencyTestResultMessage.patch();
        LatencyTestConfiguration.patch();
    }

    static changeRegion(regionId: number) {
        this.selectedRegionId = -1;
        this.goingToSelectRegionId = regionId;

        this.triggerLatencyTest(regionId);
    }

    static latencyTestsDone(): boolean {
        return MessageManager.getLatencyTestsCount() >= maxServersCount;
    }

    static shouldSpoofResult(): boolean {
        return this.selectedRegionId != -1 ||
            this.goingToSelectRegionId != -1 || this.triggeringTests;
    }

    static getBestLatencyDataString(): string {
        let data = this.getBestLatencyData();
        if (data) {
            return `${data.getPing()} ms - ${data.getServerName()}`;
        }

        return "...";
    }

    static addServersToDebugMenu(debugMenu: DebugMenu) {
        let datas = MessageManager.getLatencyTests();
        for (let i = 0; i < datas.length; i++) {
            let data = datas[i];

            debugMenu.createDebugMenuButton(`#${data.getRegionId()} - ${data.getServerName()} - ${data.getPing()}ms`, -1, -1, 0, EDebugCategory.LATENCY);
        }

        debugMenu.needToUpdateLayout();
    }

    static getBestLatencyData(): LatencyData {
        return MessageManager.getLatencyTests()[0];
    }

    static getSelectedRegion(): number {
        return LatencyManager.selectedRegionId == -1 ? LatencyManager.goingToSelectRegionId : LatencyManager.selectedRegionId;
    }

    static triggerLatencyTest(regionId: number) {
        if (this.selectedRegionId == -1) {
            for (let i = 0; i < 30; i++) {
                MessageManager.sendMessage(new TriggerStartLatencyTestMessage(i));
            }
        }

        else {
            MessageManager.sendMessage(new TriggerStartLatencyTestMessage(regionId));
        }

        this.triggeringTests = true;

        GUI.showFloaterText(LocalizationManager.getString("LATENCY_TESTS_TRIGGERED"));
    }

    static regionChanged() {
        GUI.showFloaterText(LocalizationManager.getString("BATTLE_SERVER_CHANGED"));

        Configuration.regionId = this.selectedRegionId;
        Configuration.save();
    }

    static disableSpoof() {
        this.triggeringTests = false;
        this.goingToSelectRegionId = -1;
        this.selectedRegionId = -1;

        Configuration.regionId = -1;
        Configuration.save();
    }

    static update() {
        if (this.triggeringTests) {
            if (!this.latencyTestsDone())
                return;

            let data = this.getBestLatencyData();
            if (!data) return;

            if (data.getRegionId() == this.goingToSelectRegionId) {
                this.triggeringTests = false;

                this.goingToSelectRegionId = -1;
                this.selectedRegionId = data.getRegionId();

                this.regionChanged();

                console.log(data.getRegionId());
                console.log(data.getServerName());
            }
        }
    }
}