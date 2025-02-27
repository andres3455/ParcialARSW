/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import edu.eci.arsw.threads.blackListThread;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT = 5;

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * 
     * @param ipaddress suspicious host's IP address.
     * @return Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress) {

        LinkedList<Integer> blackListOcurrences = new LinkedList<>();

        int ocurrencesCount = 0;

        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount = 0;

        for (int i = 0; i < skds.getRegisteredServersCount() && ocurrencesCount < BLACK_LIST_ALARM_COUNT; i++) {
            checkedListsCount++;

            if (skds.isInBlackListServer(i, ipaddress)) {

                blackListOcurrences.add(i);

                ocurrencesCount++;
            }
        }

        if (ocurrencesCount >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ipaddress);
        } else {
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}",
                new Object[] { checkedListsCount, skds.getRegisteredServersCount() });

        return blackListOcurrences;
    }

    public List<Integer> checkHost(String ipaddress, int N) {
        LinkedList<Integer> blackListOcurrences = new LinkedList<>();

        int ocurrencesCount = 0;

        ArrayList<BlackListThread> blackThread = new ArrayList<blackListThread>();

        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount = 0;

        @SuppressWarnings("unused")
        ArrayList<blackListThread> blackThreads;

        int secciones = skds.getRegisteredServersCount() / N;


        /** Creacion de hilos con sus respectivos parametros */
        for (int i = 0; i < N; i++) {
            if (i < N - 1) {
                blackThread.add(new blackListThread((i * secciones), ((i + 1) * secciones) - 1, ipaddress, skds));
            } else if (i == N - 1) {
                blackThread
                        .add(new blackListThread((i * secciones), skds.getRegisteredServersCount(), ipaddress, skds));
            }
            blackThread.get(i).start();
        }
        for (blackListThread thread : blackThread) {
            /** En caso que este vivo el hilo, que siga buscando la direccion */
            while (thread.isAlive()) {
                continue;
            }
            /**
             * Cuando el hilo ya haya terminado, retorne cuantas veces encontró la direccion
             * en listas negras y cuantas listas
             * reviso
             */
            ocurrencesCount += thread.malwareFounded();
            blackListOcurrences.addAll(thread.getBlackListOcurrence());
            checkedListsCount += thread.getListCount();
        }
        if (ocurrencesCount >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ipaddress);
        } else {
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}",
                new Object[] { checkedListsCount, skds.getRegisteredServersCount() });

        return blackListOcurrences;
    }

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());

}