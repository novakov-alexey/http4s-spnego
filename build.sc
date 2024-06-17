import $ivy.`com.goyeau::mill-git::0.2.5`
import $ivy.`com.lihaoyi::mill-contrib-bsp:0.8.0-15-080141`
import $ivy.`io.github.davidgregory084::mill-tpolecat:0.1.4`
import $ivy.`io.chris-kipp::mill-ci-release::0.1.10`
import $file.project.Dependencies, Dependencies.Dependencies._
import com.goyeau.mill.git.GitVersionedPublishModule
import io.github.davidgregory084.TpolecatModule
import io.kipp.mill.ci.release.CiReleaseModule
import mill._
import scalalib._
import mill.scalalib._
import mill.scalalib.publish.{Developer, License, PomSettings, VersionControl}
import mill.scalalib.scalafmt.ScalafmtModule
import mill.modules.Jvm
import ScalaVersion._

object ScalaVersion {
  val ver3 = "3.3.1"
  val ver213 = "2.13.5"
}

object `http4s-spnego` extends Cross[Http4sSpnegoModule](Seq(ver3, ver213))

trait Http4sSpnegoModule
    extends CrossScalaModule    
    with ScalafmtModule    
    with GitVersionedPublishModule 
    with CiReleaseModule {
  override def scalacOptions =
    super.scalacOptions().filter(_ != "-Wunused:imports").filter(_ != "-Wunused:explicits") ++
      (if (scalaVersion().startsWith("2.12")) Seq("-Ypartial-unification") else Seq.empty)

  override def ivyDeps =
    super.ivyDeps() ++ http4sBase ++ logging ++ kindProjector

  override def scalacPluginIvyDeps = super.scalacPluginIvyDeps() //++ betterMonadicFor

  object test extends ScalaTests {
    def testFramework = "org.scalatest.tools.Framework"
    override def ivyDeps = super.ivyDeps() ++ tests
    override def scalacOptions =
      super.scalacOptions().filter(_ != "-Wunused:params").filter(_ != "-Xfatal-warnings") ++
        (if (scalaVersion().startsWith("2.12")) Seq("-Ypartial-unification") else Seq.empty)
    def testOne(args: String*) = T.command {
      super.runMain("org.scalatest.run", args: _*)
    }
  }

  override def artifactName = "http4s-spnego"
  def pomSettings =
    PomSettings(
      description = "Kerberos SPNEGO Authentification as HTTP4s middleware",
      organization = "io.github.novakov-alexey",
      url = "https://github.com/novakov-alexey/http4s-spnego",
      licenses = Seq(License.`Apache-2.0`),
      versionControl = VersionControl.github("novakov-alexey", "http4s-spnego"),
      developers = Seq(Developer("novakov-alexey", "Alexey Novakov", "https://github.com/novakov-alexey"))
    )
}

object `test-server` extends ScalaModule {
  def scalaVersion = ScalaVersion.ver213

  override def ivyDeps =
    super.ivyDeps() ++ http4sBase ++ http4sDsl

  override def moduleDeps =
    super.moduleDeps ++ Seq(`http4s-spnego`(ScalaVersion.ver213))

  def packageIt = T {
    val dest = T.ctx().dest
    val libDir = dest / "lib"
    val binDir = dest / "bin"

    os.makeDir(libDir)
    os.makeDir(binDir)

    val allJars = packageSelfModules() ++ runClasspath()
      .map(_.path)
      .filter(path => os.exists(path) && !os.isDir(path))
      .toSeq

    allJars.foreach { file =>
      os.copy.into(file, libDir)
    }

    val runnerFile = util.Jvm.createLauncher(finalMainClass(), Agg.from(os.list(libDir)), forkArgs())

    os.move.into(runnerFile.path, binDir)

    PathRef(dest)
  }

  // package root and dependent modules with meaningful names
  def packageSelfModules = T {
    T.traverse(moduleDeps :+ this) { module =>
      module.jar
        .zip(module.artifactName)
        .zip(module.artifactId)
        .map { case ((jar, name), suffix) =>
          val namedJar = jar.path / os.up / s"$name$suffix.jar"
          os.copy(jar.path, namedJar)

          namedJar
        }
    }
  }
}
