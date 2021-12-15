#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QTimer>
#include <QFile>
#include <iostream>
#include <QString>
#include <QMap>
#include <QMapIterator>
#include <QVector>
#include <QDate>
#define NBTENTA 3

using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ancienNb=0;

    //timer de 1 seconde
    monTimer = new QTimer(this);
    connect(monTimer, SIGNAL(timeout()), this, SLOT(update()));
    monTimer->start(3000);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::debloquerIp()
{
    //boucle sur la map
    QMapIterator<QString,QVector<long>> iterateur(mapIp);
    while(iterateur.hasNext())
    {
        iterateur.next();
        QString ip=iterateur.key();
        //création du vecteur
        QVector<long> vectInfo=iterateur.value();
        int nbTenta=vectInfo[0];
        qDebug()<<"test";
        if(nbTenta==3 && QDateTime::currentMSecsSinceEpoch()-vectInfo[1]>=1000*60*1)
        {
            //recuperer l'ip
            QString cmdObtentionNbLigneBlocage="/sbin/iptables -L --line-number -n | grep "+ip+" > /home/mviougea/Documents/SIO2/QT/pare-feu/ligneSup.txt";
            qDebug()<<cmdObtentionNbLigneBlocage;
            system(cmdObtentionNbLigneBlocage.toStdString().c_str());
            //fichier ligneSup
            QFile ligneSup("/home/mviougea/Documents/SIO2/QT/pare-feu/ligneSup.txt");
            ligneSup.open(QIODevice::ReadOnly | QIODevice::Text);
            //lecture du fichier
            QTextStream out(&ligneSup);
            QString ligneLue=out.readLine();
            QString numeroL=ligneLue.split(" ").at(0);
            //initialisation déblocage
            QString cmdDeblocage="/sbin/iptables -D INPUT "+numeroL;
            //qDebug()<<cmdDeblocage;
            system(cmdDeblocage.toStdString().c_str());
            mapIp.remove(ip);
        }//fin pour 3 tentatives apres un certaine temps
    }//fin boule iterateur
}//fin classe débloquer ip

void MainWindow::update()
{
    //recuperer les dernière ligne d'un fichier
    system("wc -l /var/log/auth.log > /home/mviougea/Documents/SIO2/QT/pare-feu/log.txt");
    QFile fichier("/home/mviougea/Documents/SIO2/QT/pare-feu/log.txt");
    fichier.open(QIODevice::ReadWrite | QIODevice::Text);
    QTextStream out(&fichier);
    //nbLigne dans res
    QString res;
    out >> res;
    //calcul des nouvelles lignes
    int nbNouvelleLigne = res.toInt()-ancienNb;


    if(res.toInt()>ancienNb)
    {
        ancienNb = res.toInt();
        //command pour recuperer les erreur de password et les stocker dans un fichier temp
        QString QSnouvelleLigne ="tail -n "+QString::number(nbNouvelleLigne)+" /var/log/auth.log | grep -a 'Failed password' | cut -d' ' -f1,2,3,11,12 > /home/mviougea/Documents/SIO2/QT/pare-feu/temp.txt";
        //qDebug()<<QSnouvelleLigne;
        system(QSnouvelleLigne.toStdString().c_str());

        //ouverture fichier temp
        QFile fichierLigne("/home/mviougea/Documents/SIO2/QT/pare-feu/temp.txt");
        if(!fichierLigne.open(QIODevice::ReadWrite | QIODevice::Text))
        {
            qDebug()<<"fichier pas ouvert";
        }//fin si fichier pas ouvert
        else
        {
            qDebug()<<"fichier ouvert";
            while(!fichierLigne.atEnd())
            {
                //si ouverture lire les lignes
                QString liste=fichierLigne.readLine();
                //et les serparer dans une liste
                QStringList listeElement=liste.split(" ",QString::SkipEmptyParts);

                //affichage des informations
                qDebug()<<"";
                qDebug()<<"lecture";

                //afficher l'ip
                QString adresseIp=listeElement[3];
                qDebug()<<"adresse Ip :"<<listeElement[3];
                //afficher la date
                QString date=QString::number(QDate::currentDate().year())+" "+listeElement[0]+" "+listeElement[1];
                qDebug()<<"date :"<<date;
                //afficher l'heure
                QString heure=listeElement[2];
                qDebug()<<"heure :"<<heure;

                //recuperation de la date et heure actuelle
                QLocale english=QLocale(QLocale::English);
                QDate dateConnexion=english.toDate(date,"yyyy MMM d");
                //qDebug()<<dateConnexion;
                QDateTime dateHeureConnexion;
                dateHeureConnexion.setDate(dateConnexion);
                //qDebug()<<"test"<<dateConnexion;
                QTime heureConnexion=QTime::fromString(heure,"hh:mm:ss");
                dateHeureConnexion.setTime(heureConnexion);
                qDebug()<<"date et heure trouvé"<<dateHeureConnexion.toString("yyyy MMM d hh:mm:ss");
                qDebug()<<mapIp;
                if(QDateTime::currentDateTime().toMSecsSinceEpoch()-dateHeureConnexion.toMSecsSinceEpoch()<1000*5*60)
                {
                    //si la map contiens l'ip
                    if(mapIp.contains(adresseIp))
                    {
                        //on stock dans un vecteur avec le moment de la connection
                        QVector<long> vectInfo=mapIp.value(adresseIp);
                        vectInfo[0]++;
                        vectInfo[1]=dateHeureConnexion.toMSecsSinceEpoch();
                        mapIp[adresseIp]=vectInfo;
                        //si l'utilisateur depasse les 3 tentatives
                        if (vectInfo[0]>NBTENTA)
                        {
                            //bannissement de l'adresse ip
                            QString cmdBan="/sbin/iptables -A INPUT -s "+adresseIp+" -j DROP";
                            qDebug()<<cmdBan;
                            //ui->labelAdres
                            system(cmdBan.toStdString().c_str());
                        }//fin if nombre ed tenta
                    }//fin if contains ip

                    else
                    {
                        //sinon on ne trouve pas l'ip on la créer
                        QVector<long> vectInfo;
                        vectInfo.push_back(1);
                        vectInfo.push_back(dateHeureConnexion.toMSecsSinceEpoch());
                        mapIp[adresseIp]=vectInfo;
                    }//fin else contains ip
                }//fin if current date time
            }//fin tant que lecture
            fichierLigne.close();
        }//else lecture ddu fichier
    }//fin if si nouvelle ligne
    fichier.close();
    debloquerIp();
}//fin de la classe update()



